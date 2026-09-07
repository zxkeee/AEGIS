// Package attest signs a document so a reader can tell whether it is the one
// that was produced.
//
// A compliance report is evidence, and evidence that anyone can edit after the
// fact is not evidence. The gateway can already say what it observed; this says
// that a given file is what it said, unchanged.
//
// The document is carried as a STRING of its JSON, not as a nested object.
// That is the whole design. Signing a nested object would require the verifier
// to re-serialise it byte-for-byte before hashing, and any disagreement about
// key order, number formatting or escaping turns a valid document into a failed
// verification — or, worse, lets two different documents hash the same. Carrying
// the exact bytes removes the question: hash what is there.
package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Algorithm is the only signature algorithm this package produces or accepts.
// One algorithm and no negotiation: an attestation format with a caller-chosen
// algorithm field is the shape that produces downgrade attacks.
const Algorithm = "ed25519"

// Attestation is the proof attached to a document.
type Attestation struct {
	Algorithm string `json:"algorithm"`
	// KeyID identifies the signing key: the first 16 hex characters of the
	// SHA-256 of its public key.
	KeyID string `json:"key_id"`
	// PublicKey is the base64 verifying key, included so a reader can check the
	// signature without a side channel.
	//
	// It is NOT the trust anchor. Anyone can re-sign a modified document with
	// their own key and produce something internally consistent. A verifier must
	// compare KeyID against a key obtained independently — from the operator,
	// not from the file — which is the point of publishing the id separately.
	PublicKey string `json:"public_key"`
	// Digest is "sha256:<hex>" over the exact document bytes.
	//
	// It guards nothing the signature does not already guard — any edit that
	// breaks the digest breaks the signature too, and a forger who recomputes
	// one recomputes both. It is here so a reader without crypto tooling can
	// still say something useful: `sha256sum` the document and compare, or
	// quote the digest as the document's identity in a ticket. Verify checks it
	// first only so a changed document reports as a changed document rather
	// than as a bad signature.
	//
	// Note it covers LESS than the signature does: the digest is over the
	// document bytes alone, so that `sha256sum` on the document matches, while
	// the signature also covers signed_at.
	Digest string `json:"digest"`
	// SignedAt is when the attestation was made, RFC 3339 in UTC. It is COVERED
	// BY THE SIGNATURE (see signedMessage) — editing it invalidates the
	// attestation, which is the whole reason it is trustworthy enough to print.
	SignedAt string `json:"signed_at"`
	// Signature is the hex Ed25519 signature over the document bytes.
	Signature string `json:"signature"`
}

// Envelope is a document plus its attestation.
type Envelope struct {
	// Document is the attested JSON, verbatim. Parse it to read the report;
	// hash these exact bytes to verify it.
	Document string `json:"document"`
	// Attestation proves Document is unmodified.
	Attestation Attestation `json:"attestation"`
}

// Signer attests documents with one Ed25519 key.
type Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewSigner parses a base64 Ed25519 key: either a 32-byte seed or a 64-byte
// private key. It rejects anything else rather than deriving a key from
// whatever it was given, so a mistyped secret fails at startup instead of
// producing signatures nobody can verify.
//
// The key must be separate from the license key. That one only proves a
// deployment is entitled to run; this one asserts what a deployment observed,
// and a single key doing both means whoever can issue licences can also forge
// an audit report.
func NewSigner(b64 string) (*Signer, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("attest: signing key is not valid base64: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		priv := ed25519.NewKeyFromSeed(raw)
		return &Signer{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
	case ed25519.PrivateKeySize:
		priv := ed25519.PrivateKey(raw)
		return &Signer{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
	default:
		return nil, fmt.Errorf("attest: signing key is %d bytes; want %d (seed) or %d (private key)",
			len(raw), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

// KeyID is the short identifier of the signing key. Publish it alongside the
// public key so a reader can tell which key should have signed a document.
func (s *Signer) KeyID() string { return KeyIDOf(s.pub) }

// PublicKey returns the base64 verifying key.
func (s *Signer) PublicKey() string { return base64.StdEncoding.EncodeToString(s.pub) }

// sigContext domain-separates this signature from any other use of the same
// key. Without it, bytes signed for one purpose could be replayed as bytes
// signed for another; with it, a signature only means what this package means.
// The version suffix is what a future change to the signed construction bumps.
const sigContext = "aegis-attest-v1"

// signedMessage is the exact byte string the signature covers.
//
// It is the document AND the attestation metadata that is not otherwise bound
// — currently signed_at. Signing the body alone was the original mistake: the
// algorithm, digest, public key and key id are all recomputed or cross-checked
// during verification, so tampering with them is caught, but signed_at was
// checked by nothing. An operator could take a genuinely signed clean report
// and edit that one field, and the verifier would print the attacker's date on
// the single line an auditor reads.
//
// The separator is a newline and signed_at is RFC 3339, which contains no
// newline, so the fields cannot be slid into one another.
func signedMessage(signedAt string, body []byte) []byte {
	msg := make([]byte, 0, len(sigContext)+len(signedAt)+len(body)+2)
	msg = append(msg, sigContext...)
	msg = append(msg, '\n')
	msg = append(msg, signedAt...)
	msg = append(msg, '\n')
	return append(msg, body...)
}

// Attest serialises doc and signs it together with the time of signing.
func (s *Signer) Attest(doc any) (Envelope, error) {
	body, err := json.Marshal(doc)
	if err != nil {
		return Envelope{}, fmt.Errorf("attest: encode document: %w", err)
	}
	signedAt := time.Now().UTC().Format(time.RFC3339)
	sum := sha256.Sum256(body)
	return Envelope{
		Document: string(body),
		Attestation: Attestation{
			Algorithm: Algorithm,
			KeyID:     s.KeyID(),
			PublicKey: s.PublicKey(),
			Digest:    "sha256:" + hex.EncodeToString(sum[:]),
			SignedAt:  signedAt,
			Signature: hex.EncodeToString(ed25519.Sign(s.priv, signedMessage(signedAt, body))),
		},
	}, nil
}

// ErrTampered reports a document that does not match its attestation.
var ErrTampered = errors.New("attest: document does not match its attestation")

// Verify checks an envelope against a public key the caller obtained
// independently of the envelope. Passing env.Attestation.PublicKey here proves
// only that the file is self-consistent, which a forger can also arrange.
func Verify(env Envelope, pub ed25519.PublicKey) error {
	if env.Attestation.Algorithm != Algorithm {
		return fmt.Errorf("attest: unsupported algorithm %q", env.Attestation.Algorithm)
	}
	body := []byte(env.Document)

	// Checked before the signature purely for the error message: "the document
	// changed" is actionable, "the signature is wrong" sends the reader looking
	// at keys. Security rests entirely on the ed25519.Verify below.
	sum := sha256.Sum256(body)
	if want := "sha256:" + hex.EncodeToString(sum[:]); env.Attestation.Digest != want {
		return fmt.Errorf("%w: digest is %s, document hashes to %s",
			ErrTampered, env.Attestation.Digest, want)
	}
	// Rejected before it reaches the signed message so a malformed value cannot
	// be presented to a reader as a date. It is covered by the signature either
	// way; this is about what the field is allowed to say.
	if _, err := time.Parse(time.RFC3339, env.Attestation.SignedAt); err != nil {
		return fmt.Errorf("attest: signed_at %q is not RFC 3339: %w", env.Attestation.SignedAt, err)
	}
	sig, err := hex.DecodeString(env.Attestation.Signature)
	if err != nil {
		return fmt.Errorf("attest: signature is not valid hex: %w", err)
	}
	if !ed25519.Verify(pub, signedMessage(env.Attestation.SignedAt, body), sig) {
		return fmt.Errorf("%w: signature does not verify under the given key", ErrTampered)
	}
	if got := KeyIDOf(pub); got != env.Attestation.KeyID {
		return fmt.Errorf("attest: key_id %s does not name the key that verified it (%s)",
			env.Attestation.KeyID, got)
	}
	return nil
}

// KeyIDOf derives the short identifier of a verifying key. It is a hash of the
// key, so an id a reader trusts authenticates the key that arrives with a
// document — which is what lets a verifier pin an id instead of a whole key.
func KeyIDOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}
