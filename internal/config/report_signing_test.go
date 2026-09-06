package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func validSigningKey() string {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(seed)
}

// The signing key is optional; a gateway that never signs reports must still
// boot.
func TestValidate_ReportSigningKeyIsOptional(t *testing.T) {
	c := validBase()
	c.ReportSigningKey = ""
	if err := Validate(c); err != nil {
		t.Fatalf("an unset signing key must not block startup: %v", err)
	}
	c.ReportSigningKey = validSigningKey()
	if err := Validate(c); err != nil {
		t.Fatalf("a valid signing key was rejected: %v", err)
	}
}

// A key the gateway cannot sign with must fail at boot. The alternative is
// discovering it when an auditor asks for a signed report, which is the one
// moment it must not fail.
func TestValidate_RejectsAnUnusableSigningKey(t *testing.T) {
	for name, key := range map[string]string{
		"not base64": "This is not a key!!",
		"truncated":  base64.StdEncoding.EncodeToString(make([]byte, 20)),
		"too long":   base64.StdEncoding.EncodeToString(make([]byte, 65)),
		"a password": "correct-horse-battery-staple",
	} {
		c := validBase()
		c.ReportSigningKey = key
		err := Validate(c)
		if err == nil {
			t.Errorf("%s: accepted as a report signing key", name)
			continue
		}
		if !strings.Contains(err.Error(), "AEGIS_REPORT_SIGNING_KEY") {
			t.Errorf("%s: the error should name the variable, got %v", name, err)
		}
	}
}

// Reusing another secret here collapses two trust domains: anyone holding the
// admin token or the JWT secret could then sign an audit report in the
// gateway's name.
func TestValidate_RejectsASigningKeyReusedFromAnotherSecret(t *testing.T) {
	key := validSigningKey()

	t.Run("admin secret", func(t *testing.T) {
		c := validBase()
		c.AdminSecret = key
		c.ReportSigningKey = key
		if err := Validate(c); err == nil {
			t.Fatal("the admin secret was accepted as the report signing key")
		}
	})
	t.Run("jwt secret", func(t *testing.T) {
		c := validBase()
		c.Security.Auth.Secret = key
		c.ReportSigningKey = key
		if err := Validate(c); err == nil {
			t.Fatal("the JWT secret was accepted as the report signing key")
		}
	})
	t.Run("propagation secret", func(t *testing.T) {
		c := validBase()
		c.Security.Auth.PropagationSecret = key
		c.ReportSigningKey = key
		if err := Validate(c); err == nil {
			t.Fatal("the propagation secret was accepted as the report signing key")
		}
	})
}

// The key is a secret, so it comes from the environment like every other one.
func TestApplyEnvOverrides_ReportSigningKey(t *testing.T) {
	key := validSigningKey()
	t.Setenv("AEGIS_REPORT_SIGNING_KEY", key)

	cfg := GatewayConfig{}
	applyEnvOverrides(&cfg)
	if cfg.ReportSigningKey != key {
		t.Fatalf("ReportSigningKey = %q, want the environment value", cfg.ReportSigningKey)
	}

	if err := os.Unsetenv("AEGIS_REPORT_SIGNING_KEY"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	cfg2 := GatewayConfig{ReportSigningKey: "kept"}
	applyEnvOverrides(&cfg2)
	if cfg2.ReportSigningKey != "kept" {
		t.Errorf("an unset variable cleared the configured key")
	}
}

// The key must be unreachable from a config file: `yaml:"-"` is what keeps a
// signing key out of a repository.
func TestReportSigningKey_CannotBeSetFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/gateway.yaml"
	body := "report_signing_key: " + validSigningKey() + "\nReportSigningKey: " + validSigningKey() + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Unsetenv("AEGIS_REPORT_SIGNING_KEY"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ReportSigningKey != "" {
		t.Fatalf("a YAML file set the signing key (%q); it must come from the environment only",
			cfg.ReportSigningKey)
	}
}
