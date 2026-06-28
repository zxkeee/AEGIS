package api

import (
	"context"
	"io"
	"net/http"

	"api-gateway/internal/discovery"
)

// specOps is the narrow slice of the discovery catalog the spec/drift handlers
// need. Keeping it an interface (satisfied by *discovery.Catalog) lets the
// handlers be unit-tested with a fake, without a live PostgreSQL catalog.
type specOps interface {
	SetSpec(ctx context.Context, raw []byte) (discovery.SpecInfo, error)
	SpecMeta(ctx context.Context) (discovery.SpecInfo, bool, error)
	DeleteSpec(ctx context.Context) (bool, error)
	Drift(ctx context.Context) (discovery.DriftReport, error)
}

// maxSpecBytes caps an uploaded OpenAPI/Swagger document. Specs are inventory,
// not data; 8 MiB is generous and keeps a hostile upload from exhausting memory.
const maxSpecBytes = 8 << 20

// specReady guards the spec endpoints when discovery is disabled (no DSN).
func (h *handlers) specReady(w http.ResponseWriter) bool {
	if h.specCat == nil {
		writeError(w, http.StatusServiceUnavailable,
			"API discovery is disabled; set forensic_dsn (PostgreSQL) to enable spec drift")
		return false
	}
	return true
}

// PUT /api/discovery/spec
// Body is the raw OpenAPI 3.x / Swagger 2.0 document (YAML or JSON). It is
// parsed and validated before storage; a malformed document is rejected with
// 400 and never replaces the current spec. Scoped to the request's tenant.
func (h *handlers) putSpec(w http.ResponseWriter, r *http.Request) {
	if !h.specReady(w) {
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSpecBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "spec too large (max 8 MiB)")
		return
	}
	meta, err := h.specCat.SetSpec(r.Context(), raw)
	if err != nil {
		// ParseSpec errors are user-facing (bad document); surface the reason.
		writeError(w, http.StatusBadRequest, "invalid spec: "+err.Error())
		return
	}
	h.log.Info("admin: api spec imported", map[string]any{
		"version": meta.Version, "operations": meta.OpCount,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"version": meta.Version, "operations": meta.OpCount,
	})
}

// GET /api/discovery/spec — metadata of the tenant's uploaded spec (not the raw
// document). 404 when the tenant has uploaded none.
func (h *handlers) getSpec(w http.ResponseWriter, r *http.Request) {
	if !h.specReady(w) {
		return
	}
	meta, found, err := h.specCat.SpecMeta(r.Context())
	if err != nil {
		h.log.Error("admin: spec meta failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to fetch spec")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "no API spec uploaded for this tenant")
		return
	}
	writeJSON(w, http.StatusOK, meta)
}

// DELETE /api/discovery/spec — removes the tenant's uploaded spec.
func (h *handlers) deleteSpec(w http.ResponseWriter, r *http.Request) {
	if !h.specReady(w) {
		return
	}
	ok, err := h.specCat.DeleteSpec(r.Context())
	if err != nil {
		h.log.Error("admin: spec delete failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to delete spec")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "no API spec uploaded for this tenant")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// GET /api/discovery/drift — documented-vs-observed drift report for the
// request's tenant (undocumented endpoints + zombie documented operations).
func (h *handlers) getDrift(w http.ResponseWriter, r *http.Request) {
	if !h.specReady(w) {
		return
	}
	report, err := h.specCat.Drift(r.Context())
	if err != nil {
		h.log.Error("admin: drift report failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to build drift report")
		return
	}
	writeJSON(w, http.StatusOK, report)
}
