package license

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func TestReissue_ReplacesHardwareIDOnly(t *testing.T) {
	_, priv := genKeys(t)
	original := Claims{
		Licensee: "Acme Corp", Tier: "pilot", HardwareID: "old-machine",
		IssuedAt: time.Now().Add(-24 * time.Hour).UTC(), ExpiresAt: time.Now().Add(20 * 24 * time.Hour).UTC(),
		Features: []string{"sso"}, MaxRPS: 500,
	}
	oldSigned, err := Sign(priv, original)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	newSigned, err := Reissue(priv, []byte(oldSigned), "new-machine")
	if err != nil {
		t.Fatalf("Reissue: %v", err)
	}

	pub, _ := priv.Public().(ed25519.PublicKey)
	got, err := verify(pub, []byte(newSigned))
	if err != nil {
		t.Fatalf("reissued license does not verify: %v", err)
	}
	if got.HardwareID != "new-machine" {
		t.Errorf("HardwareID = %q, want new-machine", got.HardwareID)
	}
	if got.Licensee != original.Licensee || got.Tier != original.Tier {
		t.Errorf("Licensee/Tier changed: got %+v", got)
	}
	if !got.ExpiresAt.Equal(original.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want unchanged %v (reissue must not grant extra term)", got.ExpiresAt, original.ExpiresAt)
	}
	if len(got.Features) != 1 || got.Features[0] != "sso" || got.MaxRPS != 500 {
		t.Errorf("Features/MaxRPS changed: got %+v", got)
	}
	if !got.IssuedAt.After(original.IssuedAt) {
		t.Errorf("IssuedAt should be re-stamped to now, got %v (original %v)", got.IssuedAt, original.IssuedAt)
	}
}

func TestReissue_ExpiredLicenseRejected(t *testing.T) {
	_, priv := genKeys(t)
	expired := Claims{Licensee: "Acme Corp", Tier: "trial", HardwareID: "old-machine", ExpiresAt: time.Now().Add(-time.Hour)}
	oldSigned, err := Sign(priv, expired)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	_, err = Reissue(priv, []byte(oldSigned), "new-machine")
	if !errors.Is(err, ErrLicenseTermExpired) {
		t.Fatalf("err = %v, want ErrLicenseTermExpired", err)
	}
}

func TestReissue_NeverExpiringLicenseAllowed(t *testing.T) {
	_, priv := genKeys(t)
	c := Claims{Licensee: "Internal", Tier: "internal", HardwareID: "old-machine"} // ExpiresAt zero
	oldSigned, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Reissue(priv, []byte(oldSigned), "new-machine"); err != nil {
		t.Fatalf("Reissue on a never-expiring license: %v", err)
	}
}

func TestReissue_WrongKeyRejected(t *testing.T) {
	_, priv1 := genKeys(t)
	_, priv2 := genKeys(t) // different keypair issuing the reissue request
	c := Claims{Licensee: "Acme Corp", Tier: "pilot", HardwareID: "old-machine", ExpiresAt: time.Now().Add(time.Hour)}
	oldSigned, err := Sign(priv1, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Reissue(priv2, []byte(oldSigned), "new-machine"); err == nil {
		t.Fatal("a license signed by a different key must not be reissuable")
	}
}

func TestReissue_TamperedLicenseRejected(t *testing.T) {
	_, priv := genKeys(t)
	c := Claims{Licensee: "Acme Corp", Tier: "pilot", HardwareID: "old-machine", ExpiresAt: time.Now().Add(time.Hour)}
	oldSigned, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	tampered := "A" + oldSigned[1:]
	if _, err := Reissue(priv, []byte(tampered), "new-machine"); err == nil {
		t.Fatal("a tampered license must not be reissuable")
	}
}

func TestReissue_EmptyNewHardwareIDRejected(t *testing.T) {
	_, priv := genKeys(t)
	c := Claims{Licensee: "Acme Corp", Tier: "pilot", HardwareID: "old-machine", ExpiresAt: time.Now().Add(time.Hour)}
	oldSigned, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Reissue(priv, []byte(oldSigned), ""); err == nil {
		t.Fatal("an empty new hardware id must be rejected")
	}
}

func TestReissue_SameHardwareIDStillWorks(t *testing.T) {
	// Not the primary use case, but there's no reason to special-case it: a
	// customer re-requesting the same fingerprint (e.g. after losing the
	// .lic file, or scripted retries) should get a fresh, valid copy.
	_, priv := genKeys(t)
	c := Claims{Licensee: "Acme Corp", Tier: "pilot", HardwareID: "same-machine", ExpiresAt: time.Now().Add(time.Hour)}
	oldSigned, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Reissue(priv, []byte(oldSigned), "same-machine"); err != nil {
		t.Fatalf("Reissue with the same hardware id: %v", err)
	}
}
