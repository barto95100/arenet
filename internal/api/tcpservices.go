// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
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
	"time"

	"github.com/go-chi/chi/v5"

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

// tcpBackendResult is one line of the test report.
type tcpBackendResult struct {
	Backend string `json:"backend"`
	OK      bool   `json:"ok"`
	// Error is the dial failure, already readable; empty when OK.
	Error string `json:"error,omitempty"`
	// ElapsedMs is how long the dial took, so a backend that answers
	// but slowly is visible rather than merely "ok".
	ElapsedMs int64 `json:"elapsedMs"`
}

type tcpServiceTestResponse struct {
	Backends []tcpBackendResult `json:"backends"`
	// ProxyProtocolNote repeats, at the moment the operator tests,
	// what has to be true on the other side. A dial proves the
	// backend accepts connections; it cannot prove it expects the
	// PROXY header, and that mismatch is the failure mode of this
	// feature.
	ProxyProtocolNote string `json:"proxyProtocolNote,omitempty"`
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
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	created, err := h.store.CreateTCPService(r.Context(), svc)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	updated, err := h.store.UpdateTCPService(r.Context(), svc)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "TCP service not found")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
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
	for _, u := range svc.Upstreams {
		addr := u.Dial()
		start := time.Now()
		conn, dialErr := net.DialTimeout("tcp", addr, tcpServiceTestTimeout)
		res := tcpBackendResult{Backend: addr, ElapsedMs: time.Since(start).Milliseconds()}
		if dialErr != nil {
			res.Error = dialErr.Error()
		} else {
			res.OK = true
			_ = conn.Close()
		}
		resp.Backends = append(resp.Backends, res)
	}

	if svc.ProxyProtocol != storage.ProxyProtocolOff {
		resp.ProxyProtocolNote = fmt.Sprintf(
			"This service prepends the PROXY protocol %s header. The backend must be configured to "+
				"expect it from this host, otherwise connections fail silently. On Stalwart, that is "+
				"proxyTrustedNetworks.", svc.ProxyProtocol)
	}
	writeJSON(w, http.StatusOK, resp)
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
	return caddymgr.CanBindTCP(svc.ListenHostPort())
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
