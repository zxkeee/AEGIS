package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// testSigner returns a signer over a deterministic key.
func testSigner(t *testing.T, seedByte byte) *Signer {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	s, err := NewSigner(base64.StdEncoding.EncodeToString(seed))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func pubOf(t *testing.T, s *Signer) ed25519.PublicKey {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s.PublicKey())
	if err != nil {
		t.Fatalf("public key is not base64: %v", err)
	}
	return ed25519.PublicKey(raw)
}

type report struct {
	Findings int      `json:"findings"`
	Endpoint string   `json:"endpoint"`
	Notes    []string `json:"notes"`
}

var sample = report{Findings: 3, Endpoint: "GET /users/{id}", Notes: []string{"pii", "unauthenticated"}}

func TestAttest_RoundTripVerifies(t *testing.T) {
	s := testSigner(t, 1)
	env, err := s.Attest(sample)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if err := Verify(env, pubOf(t, s)); err != nil {
		t.Fatalf("a freshly signed document must verify: %v", err)
	}

	// The document must still be the report, not an opaque blob.
	var back report
	if err := json.Unmarshal([]byte(env.Document), &back); err != nil {
		t.Fatalf("document is not readable JSON: %v", err)
	}
	if back.Endpoint != sample.Endpoint || back.Findings != sample.Findings {
		t.Errorf("document round-tripped to %+v, want %+v", back, sample)
	}
}

// The one claim the whole package exists to make: an edited report stops
// verifying. Every single-byte edit, not just a convenient one.
func TestVerify_RejectsEveryEditToTheDocument(t *testing.T) {
	s := testSigner(t, 2)
	env, err := s.Attest(sample)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	orig := env.Document
	for i := 0; i < len(orig); i++ {
		b := []byte(orig)
		b[i] ^= 0x01
		if string(b) == orig {
			continue
		}
		env.Document = string(b)
		if err := Verify(env, pubOf(t, s)); err == nil {
			t.Fatalf("byte %d flipped and the document still verified: %q", i, env.Document)
		}
	}
}

// The realistic forgery: change the numbers, then recompute the digest so the
// file is internally consistent. Only the signature catches this.
func TestVerify_RejectsARecomputedDigest(t *testing.T) {
	s := testSigner(t, 3)
	env, _ := s.Attest(sample)

	forged, _ := s.Attest(report{Findings: 0, Endpoint: "GET /users/{id}"})
	env.Document = forged.Document
	env.Attestation.Digest = forged.Attestation.Digest // signature left alone

	err := Verify(env, pubOf(t, s))
	if err == nil {
		t.Fatal("a document with a matching digest but the old signature verified")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("error should name the signature, got %v", err)
	}
}

// The other realistic forgery: re-sign the edited report under an attacker's
// own key. The envelope is then perfectly self-consistent — which is exactly
// why the verifier must supply a key it obtained elsewhere.
func TestVerify_SelfConsistentForgeryFailsAgainstThePinnedKey(t *testing.T) {
	real := testSigner(t, 4)
	attacker := testSigner(t, 5)

	forged, err := attacker.Attest(report{Findings: 0, Endpoint: "GET /users/{id}"})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	// Self-consistent: it verifies against the key it carries.
	if err := Verify(forged, pubOf(t, attacker)); err != nil {
		t.Fatalf("the forgery should be internally consistent, got %v", err)
	}
	// And useless against the key the auditor pinned.
	if err := Verify(forged, pubOf(t, real)); err == nil {
		t.Fatal("a document signed by another key verified against the real one")
	}
	if forged.Attestation.KeyID == real.KeyID() {
		t.Fatal("distinct keys produced the same key_id")
	}
}

// key_id must name the key that actually verified, or a reader comparing it to
// a pinned id is comparing an attacker-chosen string.
func TestVerify_RejectsAKeyIDThatNamesAnotherKey(t *testing.T) {
	s := testSigner(t, 6)
	other := testSigner(t, 7)
	env, _ := s.Attest(sample)
	env.Attestation.KeyID = other.KeyID()

	if err := Verify(env, pubOf(t, s)); err == nil {
		t.Fatal("a mislabelled key_id verified")
	}
}

// An attestation naming another algorithm must be refused outright, not
// verified as ed25519 anyway.
func TestVerify_RejectsAnotherAlgorithm(t *testing.T) {
	s := testSigner(t, 8)
	env, _ := s.Attest(sample)
	env.Attestation.Algorithm = "none"
	if err := Verify(env, pubOf(t, s)); err == nil {
		t.Fatal("algorithm \"none\" was accepted")
	}
}

// The envelope crosses the wire as JSON. If encoding and decoding it altered
// the document by even one byte, every signature would fail in production and
// pass in this package's tests.
func TestEnvelope_SurvivesJSONTransport(t *testing.T) {
	s := testSigner(t, 9)
	env, _ := s.Attest(map[string]any{
		"quote":   `he said "no"`,
		"newline": "a\nb",
		"unicode": "паспорт ✓",
		"nested":  map[string]any{"n": 1.5},
	})

	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	var back Envelope
	if err := json.Unmarshal(wire, &back); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if err := Verify(back, pubOf(t, s)); err != nil {
		t.Fatalf("envelope stopped verifying after a JSON round trip: %v", err)
	}
}

func TestNewSigner_AcceptsSeedAndPrivateKey(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x2a
	}
	priv := ed25519.NewKeyFromSeed(seed)

	fromSeed, err := NewSigner(base64.StdEncoding.EncodeToString(seed))
	if err != nil {
		t.Fatalf("seed rejected: %v", err)
	}
	fromPriv, err := NewSigner(base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatalf("private key rejected: %v", err)
	}
	if fromSeed.PublicKey() != fromPriv.PublicKey() {
		t.Error("the same key in its two encodings produced different public keys")
	}
	if fromSeed.KeyID() != fromPriv.KeyID() {
		t.Error("the same key in its two encodings produced different key ids")
	}
}

// A mistyped or truncated key must fail loudly at startup. Deriving something
// usable from the wrong bytes would produce signatures nobody can verify.
func TestNewSigner_RejectsAnythingElse(t *testing.T) {
	cases := map[string]string{
		"empty":       "",
		"not base64":  "not-a-key!!",
		"too short":   base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"31 bytes":    base64.StdEncoding.EncodeToString(make([]byte, 31)),
		"33 bytes":    base64.StdEncoding.EncodeToString(make([]byte, 33)),
		"63 bytes":    base64.StdEncoding.EncodeToString(make([]byte, 63)),
		"hex not b64": "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788990",
	}
	for name, key := range cases {
		if _, err := NewSigner(key); err == nil {
			t.Errorf("%s: accepted as a signing key", name)
		}
	}
}

func TestAttest_RejectsAnUnencodableDocument(t *testing.T) {
	s := testSigner(t, 10)
	if _, err := s.Attest(map[string]any{"ch": make(chan int)}); err == nil {
		t.Fatal("an unencodable document produced an attestation")
	}
}

func TestVerify_RejectsANonHexSignature(t *testing.T) {
	s := testSigner(t, 11)
	env, _ := s.Attest(sample)
	env.Attestation.Signature = "zzzz"
	if err := Verify(env, pubOf(t, s)); err == nil {
		t.Fatal("a malformed signature verified")
	}
}

// The digest is not a security control (the signature covers the same bytes),
// but it is a published identity for the document and an operator will compare
// it with sha256sum. Pin both halves of that promise: the value, and the fact
// that an edited document is reported as an edited document rather than as a
// key problem.
func TestVerify_DigestIsTheDocumentsPublishedIdentity(t *testing.T) {
	s := testSigner(t, 12)
	env, _ := s.Attest(sample)

	sum := sha256.Sum256([]byte(env.Document))
	if want := "sha256:" + hex.EncodeToString(sum[:]); env.Attestation.Digest != want {
		t.Fatalf("digest = %s, want %s — an operator running sha256sum would see a mismatch",
			env.Attestation.Digest, want)
	}

	env.Document = strings.Replace(env.Document, `"findings":3`, `"findings":0`, 1)
	err := Verify(env, pubOf(t, s))
	if err == nil {
		t.Fatal("an edited document verified")
	}
	if !strings.Contains(err.Error(), "hashes to") {
		t.Errorf("an edited document should be reported as changed, got %v", err)
	}
	if !errors.Is(err, ErrTampered) {
		t.Errorf("error should wrap ErrTampered, got %v", err)
	}
}
