package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func genKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func withEmbeddedKey(t *testing.T, pub ed25519.PublicKey) {
	t.Helper()
	restore := SetPublicKeyForTesting(base64.StdEncoding.EncodeToString(pub))
	t.Cleanup(restore)
}

func writeLicense(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "aegis.lic")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write license: %v", err)
	}
	return path
}

func TestLoad_ValidUnexpiredLicense(t *testing.T) {
	pub, priv := genKeys(t)
	withEmbeddedKey(t, pub)
	c := Claims{Licensee: "Acme Corp", Tier: "pilot", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(30 * 24 * time.Hour)}
	sig, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := writeLicense(t, sig)

	st := Load(path)
	if !st.Valid {
		t.Fatalf("expected valid license, got reason: %s", st.Reason)
	}
	if st.Claims.Licensee != "Acme Corp" {
		t.Errorf("licensee = %q, want Acme Corp", st.Claims.Licensee)
	}
	if st.DaysLeft < 28 || st.DaysLeft > 30 {
		t.Errorf("DaysLeft = %d, want ~30", st.DaysLeft)
	}
}

func TestLoad_ExpiredLicenseIsInvalid(t *testing.T) {
	pub, priv := genKeys(t)
	withEmbeddedKey(t, pub)
	c := Claims{Licensee: "Acme Corp", Tier: "trial", IssuedAt: time.Now().Add(-60 * 24 * time.Hour), ExpiresAt: time.Now().Add(-1 * time.Hour)}
	sig, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := writeLicense(t, sig)

	st := Load(path)
	if st.Valid {
		t.Fatal("expected expired license to be invalid")
	}
	if st.Reason == "" {
		t.Error("expected a reason for the invalid license")
	}
}

func TestLoad_NeverExpiresWhenExpiresAtZero(t *testing.T) {
	pub, priv := genKeys(t)
	withEmbeddedKey(t, pub)
	c := Claims{Licensee: "Internal", Tier: "production", IssuedAt: time.Now()}
	sig, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := writeLicense(t, sig)

	st := Load(path)
	if !st.Valid {
		t.Fatalf("expected valid license, got reason: %s", st.Reason)
	}
}

func TestLoad_WrongKeyIsRejected(t *testing.T) {
	_, priv := genKeys(t)
	otherPub, _ := genKeys(t)
	withEmbeddedKey(t, otherPub) // embedded key does NOT match the signer

	c := Claims{Licensee: "Acme Corp", Tier: "pilot", ExpiresAt: time.Now().Add(30 * 24 * time.Hour)}
	sig, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := writeLicense(t, sig)

	st := Load(path)
	if st.Valid {
		t.Fatal("license signed by a different key must not verify")
	}
}

func TestLoad_TamperedClaimsRejected(t *testing.T) {
	pub, priv := genKeys(t)
	withEmbeddedKey(t, pub)
	c := Claims{Licensee: "Acme Corp", Tier: "trial", ExpiresAt: time.Now().Add(-1 * time.Hour)}
	sig, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Flip a byte in the base64 claims segment to simulate tampering (e.g.
	// trying to extend an expired trial by editing the file by hand).
	tampered := "A" + sig[1:]
	path := writeLicense(t, tampered)

	st := Load(path)
	if st.Valid {
		t.Fatal("tampered license must not verify")
	}
}

func TestLoad_MalformedFileRejected(t *testing.T) {
	pub, _ := genKeys(t)
	withEmbeddedKey(t, pub)
	path := writeLicense(t, "not-a-license-file")

	st := Load(path)
	if st.Valid {
		t.Fatal("malformed license file must not verify")
	}
}

func TestLoad_MissingFileRejected(t *testing.T) {
	pub, _ := genKeys(t)
	withEmbeddedKey(t, pub)

	st := Load(filepath.Join(t.TempDir(), "does-not-exist.lic"))
	if st.Valid {
		t.Fatal("missing license file must not verify")
	}
}

func TestLoad_EmptyPathRejected(t *testing.T) {
	st := Load("")
	if st.Valid {
		t.Fatal("empty license_path must not verify")
	}
}

func TestLoad_HardwareIDMatchesCurrentMachine(t *testing.T) {
	pub, priv := genKeys(t)
	withEmbeddedKey(t, pub)
	fp, err := Fingerprint()
	if err != nil {
		t.Skipf("cannot compute fingerprint in this environment: %v", err)
	}
	c := Claims{Licensee: "Acme Corp", Tier: "pilot", HardwareID: fp}
	sig, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := writeLicense(t, sig)

	st := Load(path)
	if !st.Valid {
		t.Fatalf("expected valid license bound to this machine's real fingerprint, got reason: %s", st.Reason)
	}
}

func TestLoad_HardwareIDMismatchRejected(t *testing.T) {
	pub, priv := genKeys(t)
	withEmbeddedKey(t, pub)
	c := Claims{Licensee: "Acme Corp", Tier: "pilot", HardwareID: "not-this-machines-fingerprint"}
	sig, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := writeLicense(t, sig)

	st := Load(path)
	if st.Valid {
		t.Fatal("license locked to a different machine's fingerprint must not verify here")
	}
	if st.Reason == "" {
		t.Error("expected a reason explaining the hardware mismatch")
	}
}

func TestLoad_EmptyHardwareIDIsUnrestricted(t *testing.T) {
	pub, priv := genKeys(t)
	withEmbeddedKey(t, pub)
	// No HardwareID set — floating/internal license, must not be checked
	// against this (or any) machine's fingerprint.
	c := Claims{Licensee: "Internal", Tier: "internal"}
	sig, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := writeLicense(t, sig)

	st := Load(path)
	if !st.Valid {
		t.Fatalf("license with no HardwareID must not be hardware-checked, got reason: %s", st.Reason)
	}
}

func TestFingerprint_DeterministicAcrossCalls(t *testing.T) {
	fp1, err := Fingerprint()
	if err != nil {
		t.Skipf("cannot compute fingerprint in this environment: %v", err)
	}
	fp2, err := Fingerprint()
	if err != nil {
		t.Fatalf("second Fingerprint() call failed: %v", err)
	}
	if fp1 != fp2 {
		t.Fatalf("Fingerprint() is not deterministic: %q != %q", fp1, fp2)
	}
	if len(fp1) != 64 { // hex-encoded SHA-256
		t.Errorf("fingerprint length = %d, want 64 (hex sha256)", len(fp1))
	}
}

func TestLoad_NoEmbeddedKeyRejectsEverything(t *testing.T) {
	// publicKeyB64 defaults to "" in an unpatched dev build — a plain `go
	// build` must never accidentally grant a full license.
	_, priv := genKeys(t)
	c := Claims{Licensee: "Acme Corp", Tier: "production"}
	sig, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := writeLicense(t, sig)

	st := Load(path) // publicKeyB64 untouched — still ""
	if st.Valid {
		t.Fatal("a dev build with no embedded key must never validate a license")
	}
}
