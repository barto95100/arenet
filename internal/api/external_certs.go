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
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// External-certificate CRUD (v2.19.0). Operator-uploaded TLS certs
// served on routes via load_pem. The private key (KeyPEM) is a SECRET:
// it is accepted on POST/PUT but NEVER echoed back — every response
// shape is passed through toExternalCertResponse, which blanks KeyPEM.
//
// Route split mirrors the maintenance-page / error-templates surface:
// the two GETs are viewer-accessible (the RouteForm dropdown lists
// certs without admin scope), the three mutations are admin-only.

// externalCertRequest is the wire shape accepted by POST and PUT.
//
// ChainPEM is a *string so PUT can distinguish three cases: absent /
// "" (keep the stored chain) from an explicit JSON null (clear it) from
// a new value (set it). On POST a nil pointer is treated as "no chain".
type externalCertRequest struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	CertPEM     string  `json:"certPEM"`
	KeyPEM      string  `json:"keyPEM"`
	ChainPEM    *string `json:"chainPEM"`
}

// externalCertResponse is the redacted wire shape returned by every
// handler. KeyPEM is always the empty string (the embedded
// ExternalCertificate.KeyPEM is blanked before marshalling, and the
// explicit field re-asserts the empty value in case the embedded tag
// changes). Warnings is only populated on POST/PUT (parse-time).
type externalCertResponse struct {
	storage.ExternalCertificate
	KeyPEM   string                `json:"keyPEM"`
	Warnings []storage.CertWarning `json:"warnings,omitempty"`
}

// toExternalCertResponse redacts the private key and wraps the record
// with any parse warnings. It is the single choke point for cert
// serialization — no handler writes an ExternalCertificate directly.
func toExternalCertResponse(c storage.ExternalCertificate, warnings []storage.CertWarning) externalCertResponse {
	c.KeyPEM = "" // redact the secret
	return externalCertResponse{ExternalCertificate: c, KeyPEM: "", Warnings: warnings}
}

// sortExternalCertsByExpiry orders certs by NotAfter ascending, so the
// soonest-to-expire (most operationally urgent) sits first in the list.
func sortExternalCertsByExpiry(certs []storage.ExternalCertificate) {
	sort.Slice(certs, func(i, j int) bool {
		return certs[i].NotAfter.Before(certs[j].NotAfter)
	})
}

func (h *Handler) listExternalCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := h.store.ListExternalCertificates(r.Context())
	if err != nil {
		h.logger.Error("list external certs", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list external certificates")
		return
	}
	sortExternalCertsByExpiry(certs)
	out := make([]externalCertResponse, 0, len(certs))
	for _, c := range certs {
		out = append(out, toExternalCertResponse(c, nil))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) getExternalCert(w http.ResponseWriter, r *http.Request) {
	c, err := h.store.GetExternalCertificate(r.Context(), chi.URLParam(r, "id"))
	if err == storage.ErrNotFound {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}
	if err != nil {
		h.logger.Error("get external cert", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to get external certificate")
		return
	}
	writeJSON(w, http.StatusOK, toExternalCertResponse(c, nil))
}

func (h *Handler) createExternalCert(w http.ResponseWriter, r *http.Request) {
	var req externalCertRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	chain := ""
	if req.ChainPEM != nil {
		chain = *req.ChainPEM
	}
	meta, warnings, err := storage.ParseExternalCert(req.CertPEM, req.KeyPEM, chain)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rec := meta // parse populated the metadata fields
	rec.Name = req.Name
	rec.Description = req.Description
	rec.CertPEM = req.CertPEM
	rec.KeyPEM = req.KeyPEM
	rec.ChainPEM = chain
	created, err := h.store.CreateExternalCertificate(r.Context(), rec)
	if err != nil {
		h.logger.Error("create external cert", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to save external certificate")
		return
	}
	h.appendAudit(r, audit.Event{Action: audit.ActionExternalCertUploaded, TargetType: "external_certificate", TargetID: created.ID})
	writeJSON(w, http.StatusCreated, toExternalCertResponse(created, warnings))
}

func (h *Handler) updateExternalCert(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	existing, err := h.store.GetExternalCertificate(r.Context(), id)
	if err == storage.ErrNotFound {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}
	if err != nil {
		h.logger.Error("get external cert for update", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load external certificate")
		return
	}

	var req externalCertRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	// Resolve the effective cert/key/chain applying preserve-on-edit:
	//   - CertPEM: empty keeps the stored leaf.
	//   - KeyPEM:  empty keeps the stored key (secret preserve-on-edit).
	//   - ChainPEM (*string): nil / "" keeps the stored chain; an
	//     explicit JSON null clears it; any other value sets it.
	certPEM := req.CertPEM
	if certPEM == "" {
		certPEM = existing.CertPEM
	}
	keyPEM := req.KeyPEM
	if keyPEM == "" {
		keyPEM = existing.KeyPEM
	}
	chainPEM := existing.ChainPEM
	if req.ChainPEM != nil {
		// Present in the payload: "" or null both mean "clear"; a
		// non-empty value replaces the stored chain. (A nil pointer —
		// the field absent from JSON — falls through to "keep".)
		chainPEM = *req.ChainPEM
	}

	certChanged := req.CertPEM != "" && req.CertPEM != existing.CertPEM

	// Always re-validate the effective leaf/key pair so an edit can
	// never leave a cert whose key no longer matches. When the cert
	// itself changed we also overwrite the metadata fields from the
	// fresh parse (spec §3.6).
	meta, warnings, err := storage.ParseExternalCert(certPEM, keyPEM, chainPEM)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	rec := existing
	rec.Name = req.Name
	rec.Description = req.Description
	rec.CertPEM = certPEM
	rec.KeyPEM = keyPEM
	rec.ChainPEM = chainPEM
	if certChanged {
		rec.Issuer = meta.Issuer
		rec.Subject = meta.Subject
		rec.SerialNumber = meta.SerialNumber
		rec.KeyAlgorithm = meta.KeyAlgorithm
		rec.SignatureAlgorithm = meta.SignatureAlgorithm
		rec.NotBefore = meta.NotBefore
		rec.NotAfter = meta.NotAfter
		rec.DNSNames = meta.DNSNames
	}

	updated, err := h.store.UpdateExternalCertificate(r.Context(), id, rec)
	if err == storage.ErrNotFound {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}
	if err != nil {
		h.logger.Error("update external cert", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to save external certificate")
		return
	}

	// Reload Caddy so any route already serving this cert picks up the
	// new material immediately (best-effort, mirrors the maintenance
	// page / error-templates update contract).
	if rerr := h.caddy.ReloadFromStore(r.Context()); rerr != nil {
		h.logger.Warn("external cert update: caddy reload failed", "err", rerr)
	}

	h.appendAudit(r, audit.Event{Action: audit.ActionExternalCertUpdated, TargetType: "external_certificate", TargetID: id})
	writeJSON(w, http.StatusOK, toExternalCertResponse(updated, warnings))
}

func (h *Handler) deleteExternalCert(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Route-reference 409 guard is added in Task 4 once Route.CertSource/CertID exist.

	if err := h.store.DeleteExternalCertificate(r.Context(), id); err == storage.ErrNotFound {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	} else if err != nil {
		h.logger.Error("delete external cert", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to delete external certificate")
		return
	}

	// Reload Caddy so the deleted cert stops being offered (best-effort).
	if rerr := h.caddy.ReloadFromStore(r.Context()); rerr != nil {
		h.logger.Warn("external cert delete: caddy reload failed", "err", rerr)
	}

	h.appendAudit(r, audit.Event{Action: audit.ActionExternalCertDeleted, TargetType: "external_certificate", TargetID: id})
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}
