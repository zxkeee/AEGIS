// Package license enforces the commercial licensing boundary for AEGIS
// deployments: without a valid signed license file, the gateway refuses to
// start at all — the same hard gate as any other config.Validate rejection
// (see cmd/gateway/main.go's loadValidatedConfig). A missing, expired,
// tampered, or wrong-hardware license means the gateway does not come up;
// there is no free degraded fallback mode, because that would still give away
// the discovery/posture/findings value for nothing.
//
// This is a deterrent and a trust-boundary marker, not DRM: a self-hosted Go
// binary can always be patched by someone with the will to do it. The goals
// are (1) an honest customer's trial clock is real and visible, (2) a copied
// deployment without a valid license does not run at all, and (3) production
// use without a license is a clear, loggable, contractual breach — not an
// ambiguous one.
package license

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// publicKeyB64 is the Ed25519 public key baked into the binary at build time
// via -ldflags "-X api-gateway/internal/license.publicKeyB64=...". It is safe
// to embed (it only lets the binary VERIFY licenses, not issue them) and MUST
// differ between the public/OSS build (if any) and the commercial build. The
// matching private key never lives in this repository — see
// docs/licensing.md — it is generated once and kept offline by whoever issues
// licenses.
//
// Empty (the default, unpatched dev build) means "no key configured": Verify
// always reports invalid, so a plain `go build` from this repo without the
// release ldflags never accidentally grants a full license.
var publicKeyB64 = ""

// SetPublicKeyForTesting overrides the embedded public key for the duration
// of a test, returning a restore func. It exists so packages other than
// license itself (e.g. cmd/gateway's tests, which need a real boot to pass a
// license check) can exercise the valid-license path without the release
// -ldflags build step. Never call this outside a test.
func SetPublicKeyForTesting(b64 string) (restore func()) {
	prev := publicKeyB64
	publicKeyB64 = b64
	return func() { publicKeyB64 = prev }
}

// Claims describes what a license grants. Signed as JSON; see Verify.
type Claims struct {
	// Licensee identifies who this license was issued to, for audit/support,
	// not enforcement.
	Licensee string `json:"licensee"`
	// Tier gates behavior in the caller (main.go): "trial" and "pilot" are
	// informational; "production" is the only tier that should be treated as
	// a green light for a customer's real traffic. Enforcement of what a tier
	// unlocks lives in the caller, not here — this package only verifies
	// authenticity and expiry.
	Tier string `json:"tier"`
	// IssuedAt / ExpiresAt bound the license's validity window. ExpiresAt
	// zero-value means "never expires" — reserved for internal/demo use, an
	// issuer should not hand this to a customer license.
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// Features is an optional allow-list the caller can consult (e.g. "sso",
	// "multitenancy"); empty means no additional restriction beyond Tier.
	Features []string `json:"features,omitempty"`
	// MaxRPS is an optional advisory cap the caller may enforce; 0 means
	// unlimited.
	MaxRPS int `json:"max_rps,omitempty"`
	// HardwareID node-locks the license to the machine it was issued for, via
	// Fingerprint(). Empty means "not hardware-locked" — floating/internal use
	// only; a customer license should always carry the value the customer
	// reported before issuance (see docs/licensing.md). If the machine's
	// current fingerprint doesn't match, Load reports the license invalid
	// (same hard-fail treatment as an expired one) with a reason that says so
	// explicitly, distinguishing it from an expiry so support isn't guessing.
	HardwareID string `json:"hardware_id,omitempty"`
}

// Fingerprint derives a stable, deterministic identifier for the machine it
// runs on, from the MAC addresses of its non-loopback network interfaces
// (sorted so interface enumeration order doesn't matter, SHA-256'd so the
// license file never carries raw MAC addresses). It changes when network
// hardware changes — swapping a NIC, migrating to different physical/virtual
// hardware — which is the intended node-locking behavior: run this before
// requesting a license, and again to prove hardware changed when requesting a
// free re-issue.
//
// Caveat, worth knowing before you rely on this: in a container (Docker/k8s)
// without a pinned MAC, the virtual NIC's address is often reassigned on
// container recreation, not just on physical hardware changes — a redeploy
// can look like a "new machine." Pin the container's MAC, or bind the license
// to the host instead of the container, if that distinction matters to a
// deployment.
func Fingerprint() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("enumerate network interfaces: %w", err)
	}
	var macs []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		macs = append(macs, iface.HardwareAddr.String())
	}
	if len(macs) == 0 {
		return "", errors.New("no network interfaces with a hardware address found")
	}
	sort.Strings(macs)
	sum := sha256.Sum256([]byte(strings.Join(macs, ",")))
	return hex.EncodeToString(sum[:]), nil
}

// Status is what main.go needs to decide whether the gateway may boot.
type Status struct {
	Valid    bool
	Reason   string // human-readable, always set when !Valid
	Claims   Claims
	Path     string
	DaysLeft int // only meaningful when Valid and ExpiresAt is set

	// HardwareMismatch is true only when Valid is false specifically because
	// the license is hardware-locked (Claims.HardwareID != "") and this
	// machine's current fingerprint doesn't match it — as opposed to any
	// other reason (expired, tampered, missing, wrong key). LoadWithGrace uses
	// this to decide whether a temporary grace period applies; a plain Load
	// caller that doesn't care about grace can ignore this field entirely.
	HardwareMismatch bool
	// CurrentFingerprint is this machine's Fingerprint(), populated whenever
	// a hardware-lock check was performed (match or mismatch alike), so a
	// caller doesn't need to recompute it.
	CurrentFingerprint string

	// Grace is true when Valid is true only because an active hardware-change
	// grace period is covering a mismatch that would otherwise fail — see
	// LoadWithGrace. A plain Load never sets this; it has no concept of
	// grace.
	Grace bool
	// GraceUntil is when the current grace period ends. Only meaningful when
	// Grace is true.
	GraceUntil time.Time
}

// license file format: "<base64(json claims)>.<base64(ed25519 signature over
// the raw json bytes)>" — deliberately not a JWT: there is exactly one
// algorithm, one key, and no header to confuse a verifier into trusting an
// attacker-chosen alg (the class of bug that hit JWT everywhere else in this
// codebase — see middleware/jwt.go's alg-confusion fix). Keep it that way.
const sep = "."

// Sign produces a license file's contents. Only ever called by the offline
// issuer tool (cmd/licensegen), never by the gateway at runtime.
func Sign(priv ed25519.PrivateKey, c Claims) (string, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, raw)
	return base64.StdEncoding.EncodeToString(raw) + sep + base64.StdEncoding.EncodeToString(sig), nil
}

// verify checks a license file's bytes against the given public key,
// independent of the package-level embedded key — used by cmd/licensegen and
// tests so they are not coupled to the build-time ldflags value.
func verify(pub ed25519.PublicKey, data []byte) (Claims, error) {
	parts := strings.SplitN(strings.TrimSpace(string(data)), sep, 2)
	if len(parts) != 2 {
		return Claims{}, errors.New("malformed license: expected \"<claims>.<signature>\"")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("malformed license claims: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("malformed license signature: %w", err)
	}
	if !ed25519.Verify(pub, raw, sig) {
		return Claims{}, errors.New("license signature does not verify")
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return Claims{}, fmt.Errorf("malformed license claims json: %w", err)
	}
	return c, nil
}

// Load reads and verifies a license file at path against the embedded
// package-level public key, returning a Status that is always safe to act on
// (never returns an error — a license problem is data for a log line and a
// forced-Observe decision, not a startup failure).
func Load(path string) Status {
	if path == "" {
		return Status{Valid: false, Reason: "no license_path configured"}
	}
	if publicKeyB64 == "" {
		return Status{Valid: false, Path: path, Reason: "binary was not built with a license public key (dev build)"}
	}
	pub, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return Status{Valid: false, Path: path, Reason: "embedded license public key is malformed"}
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path, not user input
	if err != nil {
		return Status{Valid: false, Path: path, Reason: fmt.Sprintf("cannot read license file: %v", err)}
	}
	claims, err := verify(ed25519.PublicKey(pub), data)
	if err != nil {
		return Status{Valid: false, Path: path, Reason: err.Error()}
	}
	if !claims.ExpiresAt.IsZero() && time.Now().After(claims.ExpiresAt) {
		return Status{
			Valid: false, Path: path, Claims: claims,
			Reason: fmt.Sprintf("license for %q expired %s", claims.Licensee, claims.ExpiresAt.Format(time.RFC3339)),
		}
	}
	if claims.HardwareID != "" {
		fp, err := Fingerprint()
		if err != nil {
			return Status{
				Valid: false, Path: path, Claims: claims,
				Reason: fmt.Sprintf("license for %q is hardware-locked but this machine's fingerprint could not be computed: %v", claims.Licensee, err),
			}
		}
		if fp != claims.HardwareID {
			return Status{
				Valid: false, Path: path, Claims: claims, CurrentFingerprint: fp, HardwareMismatch: true,
				Reason: fmt.Sprintf("license for %q is locked to a different machine (hardware changed since issuance) — request a free re-issue with the new fingerprint (%s)", claims.Licensee, fp),
			}
		}
	}
	days := 0
	if !claims.ExpiresAt.IsZero() {
		days = int(time.Until(claims.ExpiresAt).Hours() / 24)
	}
	return Status{Valid: true, Path: path, Claims: claims, DaysLeft: days, CurrentFingerprint: claims.HardwareID}
}
