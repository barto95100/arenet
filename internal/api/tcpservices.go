// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pires/go-proxyproto"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/caddymgr"
	"github.com/barto95100/arenet/internal/l4metrics"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.42 — TCP (layer 4) services API.
//
// Write endpoints are admin-only and audited, like the routes they sit
// next to. The one addition is POST /tcp-services/{id}/test, which
// dials the backends and reports what happened: a relay whose PROXY
// protocol setting disagrees with the backend fails *silently* (the
// backend closes or hangs), so the operator needs a way to ask before
// trusting it.

// tcpServiceTestTimeout bounds each backend dial. Long enough for a
// LAN round trip and a busy backend, short enough that testing four
// backends cannot hold a request open for a minute.
const tcpServiceTestTimeout = 3 * time.Second

// tcpProxyProbeTimeout bounds the read that follows the PROXY header.
// Long enough for a backend on the other side of a LAN to refuse,
// short enough that a protocol which waits for the client to speak
// first does not stall the report.
const tcpProxyProbeTimeout = time.Second

// What the far side did with the header we sent. Reported verbatim
// so the UI can phrase each outcome in the operator's language.
const (
	// proxyProbeNotRefused: the connection was still open when the
	// probe window closed. This is the good outcome, and it is
	// deliberately not called "accepted" — see tcpProxyProbe.
	proxyProbeNotRefused = "not-refused"
	// proxyProbeRefused: the backend hung up after reading the
	// header. It is not configured to expect one.
	proxyProbeRefused = "refused"
)

// tcpBackendResult is one line of the test report.
type tcpBackendResult struct {
	Backend string `json:"backend"`
	OK      bool   `json:"ok"`
	// Error is the dial failure, already readable; empty when OK.
	// On a skipped backend it carries the reason instead.
	Error string `json:"error,omitempty"`
	// ElapsedMs is how long the dial took, so a backend that answers
	// but slowly is visible rather than merely "ok".
	ElapsedMs int64 `json:"elapsedMs"`
	// Skipped marks a backend this test cannot speak to at all —
	// UDP, where there is no connection to open. Distinct from a
	// failure: nothing is wrong, the question is unanswerable.
	Skipped bool `json:"skipped,omitempty"`
	// ErrorCode names the reason in a form the UI can translate
	// (v2.46). Error keeps the English sentence as the fallback.
	ErrorCode string `json:"errorCode,omitempty"`
	// ProxyProtocol is proxyProbeNotRefused or proxyProbeRefused,
	// empty when the service sends no header.
	ProxyProtocol string `json:"proxyProtocol,omitempty"`
}

type tcpServiceTestResponse struct {
	Backends []tcpBackendResult `json:"backends"`
	// ProxyProtocolNote repeats, at the moment the operator tests,
	// what has to be true on the other side — the pairing whose
	// mismatch is the silent failure mode of this feature.
	ProxyProtocolNote string `json:"proxyProtocolNote,omitempty"`
	// ProxyProtocolVersion lets the UI compose that note in the
	// operator's language (v2.46); the note above is the fallback.
	ProxyProtocolVersion string `json:"proxyProtocolVersion,omitempty"`
}

func (h *Handler) listTCPServices(w http.ResponseWriter, r *http.Request) {
	services, err := h.store.ListTCPServices(r.Context())
	if err != nil {
		h.logger.Error("list tcp services", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load TCP services")
		return
	}
	writeJSON(w, http.StatusOK, services)
}

// tcpServicesMetrics reports what each relay has carried since the
// process started. v2.42 — layer-4 traffic never crosses the HTTP
// chain, so without this endpoint a relay is a service nobody can
// watch: no dashboard row, no counter, no way to tell whether anyone
// ever connected.
func (h *Handler) tcpServicesMetrics(w http.ResponseWriter, r *http.Request) {
	reg := l4metrics.GlobalRegistry()
	if reg == nil {
		// No registry installed (a unit-test binary, or a boot that
		// has not reached the wiring yet): an empty object is the
		// honest answer, not a 500.
		writeJSON(w, http.StatusOK, map[string]l4metrics.ServiceCounters{})
		return
	}
	writeJSON(w, http.StatusOK, reg.Snapshot())
}

func (h *Handler) getTCPService(w http.ResponseWriter, r *http.Request) {
	svc, err := h.store.GetTCPService(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "TCP service not found")
			return
		}
		h.logger.Error("get tcp service", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load TCP service")
		return
	}
	writeJSON(w, http.StatusOK, svc)
}

func (h *Handler) createTCPService(w http.ResponseWriter, r *http.Request) {
	var svc storage.TCPService
	if err := decodeJSONBody(w, r, &svc); err != nil {
		return
	}
	svc.ID = "" // assigned by the store

	if err := h.checkTCPListen(r, svc, ""); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}

	created, err := h.store.CreateTCPService(r.Context(), svc)
	if err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		// The service is not live; leaving the row behind would show
		// the operator a service that serves nothing.
		if rbErr := h.store.DeleteTCPService(r.Context(), created.ID); rbErr != nil {
			h.logger.Error("rollback of tcp service create failed, DB and Caddy may diverge",
				"err", rbErr, "id", created.ID)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionTCPServiceCreated,
		TargetType: "tcp_service",
		TargetID:   created.ID,
		AfterJSON:  mustMarshalForAudit(created),
	})
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handler) updateTCPService(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	previous, err := h.store.GetTCPService(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "TCP service not found")
			return
		}
		h.logger.Error("get tcp service for update", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load TCP service")
		return
	}

	var svc storage.TCPService
	if err := decodeJSONBody(w, r, &svc); err != nil {
		return
	}
	svc.ID = id

	if err := h.checkTCPListen(r, svc, id); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}

	updated, err := h.store.UpdateTCPService(r.Context(), svc)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "TCP service not found")
			return
		}
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		if _, rbErr := h.store.UpdateTCPService(r.Context(), previous); rbErr != nil {
			h.logger.Error("rollback of tcp service update failed, DB and Caddy may diverge",
				"err", rbErr, "id", id)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionTCPServiceUpdated,
		TargetType: "tcp_service",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(previous),
		AfterJSON:  mustMarshalForAudit(updated),
	})
	writeJSON(w, http.StatusOK, updated)
}

func (h *Handler) deleteTCPService(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	previous, err := h.store.GetTCPService(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "TCP service not found")
			return
		}
		h.logger.Error("get tcp service for delete", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load TCP service")
		return
	}

	if err := h.store.DeleteTCPService(r.Context(), id); err != nil {
		h.logger.Error("delete tcp service", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to delete TCP service")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		if _, rbErr := h.store.CreateTCPService(r.Context(), previous); rbErr != nil {
			h.logger.Error("rollback of tcp service delete failed, DB and Caddy may diverge",
				"err", rbErr, "id", id)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionTCPServiceDeleted,
		TargetType: "tcp_service",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(previous),
	})
	w.WriteHeader(http.StatusNoContent)
}

// testTCPService dials every backend of a stored service and reports
// what happened, so the operator can check the far side before
// trusting the relay.
func (h *Handler) testTCPService(w http.ResponseWriter, r *http.Request) {
	svc, err := h.store.GetTCPService(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "TCP service not found")
			return
		}
		h.logger.Error("get tcp service for test", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load TCP service")
		return
	}

	resp := tcpServiceTestResponse{Backends: make([]tcpBackendResult, 0, len(svc.Upstreams))}
	if svc.ProxyProtocol != storage.ProxyProtocolOff {
		resp.ProxyProtocolVersion = svc.ProxyProtocol
		resp.ProxyProtocolNote = fmt.Sprintf(
			"This service prepends the PROXY protocol %s header. The backend must be configured to "+
				"expect it from this host, otherwise connections fail silently. On Stalwart, that is "+
				"proxyTrustedNetworks.", svc.ProxyProtocol)
	}

	// UDP has no connection to open. The previous version dialled TCP
	// regardless of the service's protocol, so every UDP relay was
	// reported broken while working perfectly — a wrong answer is
	// worse than no answer, and this says so instead.
	if svc.Network() == storage.TCPServiceProtocolUDP {
		for _, u := range svc.Upstreams {
			resp.Backends = append(resp.Backends, tcpBackendResult{
				Backend:   u.Dial(),
				Skipped:   true,
				ErrorCode: "udp_not_testable",
				Error: "UDP is connectionless: there is no handshake to attempt, so Arenet cannot " +
					"prove this backend is reachable without speaking its protocol.",
			})
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	src, dst := tcpProbeAddrs(r, svc)
	for _, u := range svc.Upstreams {
		resp.Backends = append(resp.Backends, tcpProbeBackend(svc, u, src, dst))
	}
	writeJSON(w, http.StatusOK, resp)
}

// tcpProbeBackend dials one backend and, when the service is
// configured to prepend a PROXY header, sends a real one and watches
// what comes back.
//
// v2.43 — the dial alone was the weaker half of this feature. It
// proved the backend accepts connections, which is rarely the thing
// in doubt, and stayed silent about the pairing that actually breaks
// relays. Worse, once a backend is configured to expect the header,
// the bare dial writes a "proxy protocol error / end of stream" line
// into its log on every click.
func tcpProbeBackend(svc storage.TCPService, u storage.TCPUpstream, src, dst net.Addr) tcpBackendResult {
	addr := u.Dial()
	start := time.Now()
	conn, dialErr := net.DialTimeout("tcp", addr, tcpServiceTestTimeout)
	res := tcpBackendResult{Backend: addr, ElapsedMs: time.Since(start).Milliseconds()}
	if dialErr != nil {
		res.Error = dialErr.Error()
		return res
	}
	defer func() { _ = conn.Close() }()
	res.OK = true

	if svc.ProxyProtocol == storage.ProxyProtocolOff {
		return res
	}

	version := byte(2)
	if svc.ProxyProtocol == storage.ProxyProtocolV1 {
		version = 1
	}
	// A nil header means the two addresses are not a pair this
	// version can express (mixed families). Say nothing rather than
	// report an outcome we did not measure.
	header := proxyproto.HeaderProxyFromAddrs(version, src, dst)
	if header == nil {
		return res
	}
	header.Command = proxyproto.PROXY
	// A write that fails here means the far side hung up while the
	// header was going out, which is the same answer as hanging up
	// just after — a refusal, not a broken backend. The dial already
	// proved the backend is up, so OK stays true.
	if _, err := header.WriteTo(conn); err != nil {
		res.ProxyProtocol = proxyProbeRefused
		return res
	}
	res.ProxyProtocol = tcpProxyProbe(conn)
	return res
}

// tcpProxyProbe asks the one question a dial cannot: did the backend
// refuse the header?
//
// What marks a refusal is the close, not the silence and not the
// bytes. A backend that does not expect the header reads it as its
// own protocol, fails to parse it, and hangs up — often after sending
// something first, the way Stalwart answers a 7-byte TLS alert on an
// implicit-TLS port. A backend that does expect it consumes the
// header and waits for the real client to speak, which on that same
// port means saying nothing at all. So bytes received prove nothing
// either way; the connection still being open is what matters.
//
// Hence proxyProbeNotRefused rather than "accepted": this establishes
// that the far side did not reject the header, which is as much as a
// single connection can honestly establish.
func tcpProxyProbe(conn net.Conn) string {
	_ = conn.SetReadDeadline(time.Now().Add(tcpProxyProbeTimeout))
	buf := make([]byte, 512)
	for {
		if _, err := conn.Read(buf); err != nil {
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				return proxyProbeNotRefused
			}
			return proxyProbeRefused
		}
		// Data is not an answer — keep reading until the deadline
		// decides, or the far side hangs up.
	}
}

// tcpProbeAddrs builds the pair of addresses the PROXY header will
// carry: the operator's own address as the client, and the service's
// listen address as the destination.
//
// Claiming the operator's address is both true and useful — the line
// this test leaves in the backend's log names whoever pressed the
// button, instead of an invented address nobody can trace.
func tcpProbeAddrs(r *http.Request, svc storage.TCPService) (net.Addr, net.Addr) {
	host, portStr, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ip = net.IPv4(127, 0, 0, 1)
	}
	port, _ := strconv.Atoi(portStr)

	listen := net.ParseIP(svc.ListenAddr)
	// The header's two addresses must share a family, so the
	// destination follows the source rather than the configuration.
	if listen == nil || listen.IsUnspecified() || (listen.To4() != nil) != (ip.To4() != nil) {
		if ip.To4() != nil {
			listen = net.IPv4zero
		} else {
			listen = net.IPv6zero
		}
	}
	return &net.TCPAddr{IP: ip, Port: port}, &net.TCPAddr{IP: listen, Port: svc.ListenPort}
}

// checkTCPListen refuses a listen address that would fight with Arenet
// itself or with another service, and refuses a port this process
// cannot actually bind — while the operator is looking at the form,
// not at the next reload.
//
// excludeID lets an update ignore the row it is replacing.
func (h *Handler) checkTCPListen(r *http.Request, svc storage.TCPService, excludeID string) error {
	// Validate first: ListenHostPort on an unvalidated service would
	// happily render a nonsense address.
	if err := svc.Validate(); err != nil {
		return err
	}

	existing, err := h.store.ListTCPServices(r.Context())
	if err != nil {
		return errors.New("failed to load the existing TCP services")
	}
	others := make([]storage.TCPService, 0, len(existing)+1)
	for _, e := range existing {
		if e.ID != excludeID {
			others = append(others, e)
		}
	}
	others = append(others, svc)

	if err := caddymgr.ValidateTCPListen(others, h.reservedTCPPorts()); err != nil {
		return err
	}
	if svc.Disabled {
		// Nothing will be bound, so there is nothing to prove.
		return nil
	}

	// v2.44.1 — do not probe an address this very service already
	// holds.
	//
	// The probe opens the port to prove it is free. On an UPDATE that
	// leaves the address alone, the port is not free: Arenet is
	// listening on it, for this service. Every edit of a live service
	// was therefore refused with "something else on this host already
	// uses it", the something else being Arenet. The conflict check
	// above already excludes the row being replaced; the probe did
	// not know about it.
	//
	// Still probed when the address changed (the new one must be
	// free) or when the service was disabled and is being enabled
	// (nothing was bound, so nothing is proven yet).
	for _, e := range existing {
		if e.ID == excludeID && !e.Disabled && e.ListenAddress() == svc.ListenAddress() {
			return nil
		}
	}
	return caddymgr.CanBind(svc.Network(), svc.ListenHostPort())
}

// decodeJSONBody is the small wrapper the TCP handlers share: it
// answers the client on a malformed body and tells the caller to stop.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return err
	}
	return nil
}
