package license

import (
	"os"
	"testing"
	"time"
)

func TestLoadWithGrace_FirstMismatchGrantsGrace(t *testing.T) {
	pub, priv := genKeys(t)
	withEmbeddedKey(t, pub)
	c := Claims{Licensee: "Acme Corp", Tier: "pilot", HardwareID: "some-other-machine"}
	sig, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := writeLicense(t, sig)

	st := LoadWithGrace(path, time.Hour)
	if !st.Valid {
		t.Fatalf("expected grace to allow boot on first mismatch, got reason: %s", st.Reason)
	}
	if !st.Grace {
		t.Fatal("expected Grace=true on a first-seen hardware mismatch")
	}
	if st.GraceUntil.IsZero() {
		t.Fatal("expected GraceUntil to be set")
	}

	// The grace state file must persist next to the license.
	if _, err := os.Stat(path + graceSuffix); err != nil {
		t.Fatalf("expected grace state file to be written: %v", err)
	}
}

func TestLoadWithGrace_SecondBootWithinWindowStillPasses(t *testing.T) {
	pub, priv := genKeys(t)
	withEmbeddedKey(t, pub)
	c := Claims{Licensee: "Acme Corp", Tier: "pilot", HardwareID: "some-other-machine"}
	sig, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := writeLicense(t, sig)

	first := LoadWithGrace(path, time.Hour)
	if !first.Valid {
		t.Fatalf("first boot: expected grace, got reason: %s", first.Reason)
	}

	second := LoadWithGrace(path, time.Hour)
	if !second.Valid || !second.Grace {
		t.Fatalf("second boot within window: expected continued grace, got Valid=%v Grace=%v reason=%s",
			second.Valid, second.Grace, second.Reason)
	}
	if !second.GraceUntil.Equal(first.GraceUntil) {
		t.Fatalf("grace deadline moved between boots (%v -> %v); it must stay fixed once granted",
			first.GraceUntil, second.GraceUntil)
	}
}

func TestLoadWithGrace_ExpiredGraceHardFails(t *testing.T) {
	pub, priv := genKeys(t)
	withEmbeddedKey(t, pub)
	c := Claims{Licensee: "Acme Corp", Tier: "pilot", HardwareID: "some-other-machine"}
	sig, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := writeLicense(t, sig)

	// Grant a grace window that is already in the past.
	first := LoadWithGrace(path, -time.Hour)
	if first.Valid {
		t.Fatal("a grace window granted entirely in the past must not validate the very first time either")
	}

	second := LoadWithGrace(path, -time.Hour)
	if second.Valid {
		t.Fatal("expired grace must hard-fail on a later boot")
	}
	if second.Grace {
		t.Fatal("Grace must be false once the window has elapsed")
	}
}

func TestLoadWithGrace_DifferentMismatchGetsFreshWindow(t *testing.T) {
	pub, priv := genKeys(t)
	withEmbeddedKey(t, pub)
	c := Claims{Licensee: "Acme Corp", Tier: "pilot", HardwareID: "machine-A"}
	sig, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := writeLicense(t, sig)

	// Exhaust a grace window for one presumed current fingerprint by writing
	// a stale grace-state file directly, as if an earlier run recorded a
	// different mismatched fingerprint than what this environment actually
	// reports.
	stale := graceState{MismatchedFingerprint: "totally-different-fingerprint", FirstSeen: time.Now().Add(-2 * time.Hour), Until: time.Now().Add(-time.Hour)}
	if err := writeGraceState(path+graceSuffix, stale); err != nil {
		t.Fatalf("write stale grace state: %v", err)
	}

	// This machine's actual mismatch (against HardwareID "machine-A") differs
	// from the stale record's fingerprint, so it must be treated as a new,
	// first-seen mismatch and get a fresh window rather than inheriting the
	// expired one.
	st := LoadWithGrace(path, time.Hour)
	if !st.Valid || !st.Grace {
		t.Fatalf("a differently-fingerprinted mismatch must get a fresh grace window, got Valid=%v Grace=%v reason=%s",
			st.Valid, st.Grace, st.Reason)
	}
}

func TestLoadWithGrace_ValidLicenseCleansUpStaleGraceFile(t *testing.T) {
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

	// Simulate a leftover grace file from a previously mismatched license
	// that has since been replaced by a correct one.
	stale := graceState{MismatchedFingerprint: "old-mismatch", FirstSeen: time.Now(), Until: time.Now().Add(time.Hour)}
	if err := writeGraceState(path+graceSuffix, stale); err != nil {
		t.Fatalf("write stale grace state: %v", err)
	}

	st := LoadWithGrace(path, time.Hour)
	if !st.Valid || st.Grace {
		t.Fatalf("a genuinely matching license must be plain-valid, not grace: Valid=%v Grace=%v", st.Valid, st.Grace)
	}
	if _, err := os.Stat(path + graceSuffix); !os.IsNotExist(err) {
		t.Fatal("expected the stale grace file to be removed once a valid license is in place")
	}
}

func TestLoadWithGrace_NonHardwareInvalidityUnaffected(t *testing.T) {
	pub, priv := genKeys(t)
	withEmbeddedKey(t, pub)
	// Expired, no HardwareID at all — grace must never apply here.
	c := Claims{Licensee: "Acme Corp", Tier: "trial", ExpiresAt: time.Now().Add(-time.Hour)}
	sig, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := writeLicense(t, sig)

	st := LoadWithGrace(path, time.Hour)
	if st.Valid {
		t.Fatal("an expired license with no hardware lock must still hard-fail under LoadWithGrace")
	}
	if st.Grace {
		t.Fatal("Grace must never be set for a non-hardware invalidity reason")
	}
	if _, err := os.Stat(path + graceSuffix); !os.IsNotExist(err) {
		t.Fatal("no grace file should be written for a non-hardware-mismatch invalidity")
	}
}
