package api

import (
	"fmt"
	"net/http"
	"strconv"

	"api-gateway/internal/attest"
)

// writeSignable writes doc, attested when the caller asked for a signature.
//
// The refusals below are the point of the helper. A caller that asks for a
// signature and gets an unsigned document has no protection at all — it is a
// script, it will not notice, and the whole reason for signing is that someone
// downstream will treat the file as evidence. So an unsatisfiable request for a
// signature is an error, never a quietly unsigned answer.
func (h *handlers) writeSignable(w http.ResponseWriter, r *http.Request, doc any) {
	sign, err := wantsSignature(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !sign {
		writeJSON(w, http.StatusOK, doc)
		return
	}
	if h.reportSigner == nil {
		writeError(w, http.StatusBadRequest,
			"report signing is not configured: set AEGIS_REPORT_SIGNING_KEY to a base64 Ed25519 key "+
				"(see docs/compliance-evidence.md) and restart")
		return
	}
	env, err := h.reportSigner.Attest(doc)
	if err != nil {
		h.log.Error("admin: report signing failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to sign report")
		return
	}
	writeJSON(w, http.StatusOK, env)
}

// wantsSignature reads ?sign. An unparseable value is rejected rather than read
// as false, for the same reason writeSignable refuses: "sign=yes" silently
// returning an unsigned document is the failure mode worth preventing.
func wantsSignature(r *http.Request) (bool, error) {
	v := r.URL.Query().Get("sign")
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("sign must be true or false, got %q", v)
	}
	return b, nil
}

// getSigningKey publishes the identity of the report signing key.
//
// It is deliberately a second channel. The public key travels inside every
// signed report so a reader can check the signature offline, but a forger can
// re-sign a modified report under their own key and produce a document that
// verifies against itself. Trust comes from having obtained the key id
// somewhere other than the document being checked: here, over the authenticated
// admin API, once, to be pinned.
func (h *handlers) getSigningKey(w http.ResponseWriter, r *http.Request) {
	if h.reportSigner == nil {
		writeError(w, http.StatusNotFound, "no report signing key is configured")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"algorithm":  attest.Algorithm,
		"key_id":     h.reportSigner.KeyID(),
		"public_key": h.reportSigner.PublicKey(),
		"note": "pin this key_id out of band; the public_key embedded in a signed report " +
			"proves only that the report is self-consistent",
	})
}
