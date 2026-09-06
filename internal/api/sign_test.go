package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api-gateway/internal/attest"
	"api-gateway/internal/logger"
)

func signerFixture(t *testing.T) *attest.Signer {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x7f
	}
	s, err := attest.NewSigner(base64.StdEncoding.EncodeToString(seed))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func signPubKey(t *testing.T, s *attest.Signer) ed25519.PublicKey {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s.PublicKey())
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return ed25519.PublicKey(raw)
}

// callSignable runs writeSignable for one query string.
func callSignable(t *testing.T, h *handlers, query string, doc any) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.writeSignable(rec, httptest.NewRequest(http.MethodGet, "/api/report?"+query, nil), doc)
	return rec
}

var docFixture = map[string]any{"count": 2, "posture": "partial"}

// The refusal that matters. A caller asking for a signature on a gateway with
// no key must be told; handing back an unsigned document would leave a script
// treating an unverifiable file as evidence.
func TestWriteSignable_RefusesWhenNoKeyIsConfigured(t *testing.T) {
	h := &handlers{log: logger.New("error")}
	rec := callSignable(t, h, "sign=1", docFixture)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — an unsatisfiable signature request answered anyway", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "posture") {
		t.Errorf("the report was returned unsigned: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "AEGIS_REPORT_SIGNING_KEY") {
		t.Errorf("the error should name the variable to set, got %s", rec.Body.String())
	}
}

// "sign=yes" is a caller who wants a signature and got the spelling wrong.
// Reading it as false hands them an unsigned document they asked to be signed.
func TestWriteSignable_RefusesAnUnparseableSignParameter(t *testing.T) {
	h := &handlers{log: logger.New("error"), reportSigner: signerFixture(t)}
	for _, q := range []string{"sign=yes", "sign=on", "sign=please"} {
		rec := callSignable(t, h, q, docFixture)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", q, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "posture") {
			t.Errorf("%s: returned a document anyway: %s", q, rec.Body.String())
		}
	}
}

func TestWriteSignable_UnsignedByDefault(t *testing.T) {
	h := &handlers{log: logger.New("error"), reportSigner: signerFixture(t)}
	for _, q := range []string{"", "sign=0", "sign=false"} {
		rec := callSignable(t, h, q, docFixture)
		if rec.Code != http.StatusOK {
			t.Fatalf("%q: status = %d, want 200", q, rec.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%q: not JSON: %v", q, err)
		}
		if _, wrapped := body["attestation"]; wrapped {
			t.Errorf("%q: the document was wrapped in an envelope nobody asked for", q)
		}
		if body["posture"] != "partial" {
			t.Errorf("%q: body = %v, want the plain report", q, body)
		}
	}
}

// The whole feature, end to end at the handler: what comes back over HTTP
// verifies against the key, and the document inside is the report.
func TestWriteSignable_SignedResponseVerifies(t *testing.T) {
	signer := signerFixture(t)
	h := &handlers{log: logger.New("error"), reportSigner: signer}
	rec := callSignable(t, h, "sign=true", docFixture)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var env attest.Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("response is not an envelope: %v (%s)", err, rec.Body.String())
	}
	if err := attest.Verify(env, signPubKey(t, signer)); err != nil {
		t.Fatalf("the signed response does not verify: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(env.Document), &doc); err != nil {
		t.Fatalf("document is not JSON: %v", err)
	}
	if doc["posture"] != "partial" {
		t.Errorf("document = %v, want the report that was passed in", doc)
	}
	if env.Attestation.KeyID != signer.KeyID() {
		t.Errorf("key_id = %s, want %s", env.Attestation.KeyID, signer.KeyID())
	}
}

// A document that cannot be encoded must not be reported as a success with an
// empty envelope.
func TestWriteSignable_UnencodableDocumentIsAnError(t *testing.T) {
	h := &handlers{log: logger.New("error"), reportSigner: signerFixture(t)}
	rec := callSignable(t, h, "sign=1", map[string]any{"ch": make(chan int)})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// The key endpoint is the second channel that makes verification mean anything:
// the auditor pins this key_id, then checks reports against it.
func TestGetSigningKey(t *testing.T) {
	signer := signerFixture(t)
	h := &handlers{log: logger.New("error"), reportSigner: signer}

	rec := httptest.NewRecorder()
	h.getSigningKey(rec, httptest.NewRequest(http.MethodGet, "/api/report/signing-key", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if body["key_id"] != signer.KeyID() || body["public_key"] != signer.PublicKey() {
		t.Errorf("body = %v, want the live signing key", body)
	}
	if body["algorithm"] != attest.Algorithm {
		t.Errorf("algorithm = %v, want %s", body["algorithm"], attest.Algorithm)
	}
	// The endpoint is reachable by every admin token; it must publish the
	// verifying key and nothing else. Leaking the seed here would let any
	// console user sign a report in the gateway's name.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x7f
	}
	priv := ed25519.NewKeyFromSeed(seed)
	for name, secret := range map[string][]byte{"seed": seed, "private key": priv} {
		if strings.Contains(rec.Body.String(), base64.StdEncoding.EncodeToString(secret)) {
			t.Fatalf("the response exposes the signing %s", name)
		}
	}

	// Without a key the endpoint must say so rather than invent one.
	empty := &handlers{log: logger.New("error")}
	rec2 := httptest.NewRecorder()
	empty.getSigningKey(rec2, httptest.NewRequest(http.MethodGet, "/api/report/signing-key", nil))
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("no key configured: status = %d, want 404", rec2.Code)
	}
}

// End to end against a real catalog: the document an auditor receives from
// /api/report verifies, and the endpoints inside it are the ones the gateway
// observed. Skips without POSTGRES_DSN.
func TestGetReport_SignedDocumentVerifiesAndCarriesTheReport(t *testing.T) {
	h := seededCatalogHandlers(t)
	signer := signerFixture(t)
	h.reportSigner = signer

	rec := httptest.NewRecorder()
	h.getReport(rec, httptest.NewRequest(http.MethodGet, "/api/report?sign=1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}

	var env attest.Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("not an envelope: %v (%s)", err, rec.Body.String())
	}
	if err := attest.Verify(env, signPubKey(t, signer)); err != nil {
		t.Fatalf("the report served over HTTP does not verify: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(env.Document), &doc); err != nil {
		t.Fatalf("document is not JSON: %v", err)
	}
	for _, k := range []string{"generated_at", "coverage", "posture", "endpoints", "count"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("the signed document is missing %q — signing must not strip the report", k)
		}
	}
	if n, _ := doc["count"].(float64); n < 2 {
		t.Errorf("count = %v, want the seeded endpoints", doc["count"])
	}

	// Editing the served document breaks it, which is the property an auditor
	// is relying on.
	env.Document = strings.Replace(env.Document, `"count"`, `"cuont"`, 1)
	if err := attest.Verify(env, signPubKey(t, signer)); err == nil {
		t.Fatal("an edited report still verified")
	}
}

// CSV cannot carry an attestation. Answering an unsigned spreadsheet to a
// request that asked for a signature is the silent downgrade this path exists
// to prevent. Skips without POSTGRES_DSN.
func TestGetReport_RefusesToSignCSV(t *testing.T) {
	h := seededCatalogHandlers(t)
	h.reportSigner = signerFixture(t)

	rec := httptest.NewRecorder()
	h.getReport(rec, httptest.NewRequest(http.MethodGet, "/api/report?format=csv&sign=1", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — an unsigned CSV answered a request for a signature", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "/orders/") {
		t.Errorf("the CSV was served anyway: %s", rec.Body.String())
	}

	// Unsigned CSV still works.
	rec2 := httptest.NewRecorder()
	h.getReport(rec2, httptest.NewRequest(http.MethodGet, "/api/report?format=csv", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("plain CSV = %d, want 200", rec2.Code)
	}
}

// The compliance report is the document that actually goes to an auditor, so
// it must be signable on the same terms. Skips without POSTGRES_DSN.
func TestGetCompliance_IsSignable(t *testing.T) {
	h := seededCatalogHandlers(t)
	signer := signerFixture(t)
	h.reportSigner = signer

	rec := httptest.NewRecorder()
	h.getCompliance(rec, httptest.NewRequest(http.MethodGet, "/api/compliance?sign=1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var env attest.Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("not an envelope: %v", err)
	}
	if err := attest.Verify(env, signPubKey(t, signer)); err != nil {
		t.Fatalf("the compliance report does not verify: %v", err)
	}
	if !strings.Contains(env.Document, "frameworks") {
		t.Errorf("the signed document is not the compliance report: %s", env.Document)
	}
}
