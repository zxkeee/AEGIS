package config

import (
	"os"
	"strings"
	"testing"
)

// TestValidateWAF_ParanoiaLevel restores coverage that was lost when the
// waf/owasp-crs branch was never merged: the CRS feature itself was
// reimplemented on main, but this file went with the branch, leaving
// validateWAF's rules with no test at all.
//
// Its original expectations are reproduced unchanged, including "pl set without
// crs" -> error. That case had stopped holding: main validated paranoia_level
// only INSIDE the use_crs branch, so setting it without CRS was silently
// ignored rather than refused. The lost test was right and the code had drifted.
func TestValidateWAF_ParanoiaLevel(t *testing.T) {
	cases := []struct {
		name    string
		crs     bool
		pl      int
		wantErr bool
	}{
		{"unset ok", false, 0, false},
		{"crs pl1", true, 1, false},
		{"crs pl4", true, 4, false},
		{"crs pl5 invalid", true, 5, true},
		{"crs pl negative", true, -1, true},
		{"pl set without crs", false, 2, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := validBase()
			cfg.Security.WAF = WAFConfig{Enabled: true, UseCRS: c.crs, ParanoiaLevel: c.pl}
			if err := Validate(cfg); (err != nil) != c.wantErr {
				t.Errorf("Validate err=%v, wantErr=%v", err, c.wantErr)
			}
		})
	}
}

// anomaly_threshold is the same shape: meaningful only under CRS, so setting it
// without CRS is a setting that reads as a control and is not one.
func TestValidateWAF_AnomalyThreshold(t *testing.T) {
	cases := []struct {
		name    string
		crs     bool
		at      int
		wantErr bool
	}{
		{"unset ok", false, 0, false},
		{"crs threshold", true, 10, false},
		{"crs negative", true, -1, true},
		{"threshold set without crs", false, 5, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := validBase()
			cfg.Security.WAF = WAFConfig{Enabled: true, UseCRS: c.crs, AnomalyThreshold: c.at}
			if err := Validate(cfg); (err != nil) != c.wantErr {
				t.Errorf("Validate err=%v, wantErr=%v", err, c.wantErr)
			}
		})
	}
}

// The rejection must say WHY, or an operator reads it as the setting being
// invalid rather than inapplicable and simply changes the number.
func TestValidateWAF_RejectionNamesTheCause(t *testing.T) {
	cfg := validBase()
	cfg.Security.WAF = WAFConfig{Enabled: true, UseCRS: false, ParanoiaLevel: 4}
	err := Validate(cfg)
	if err == nil {
		t.Fatal("paranoia_level without use_crs must be rejected")
	}
	for _, want := range []string{"paranoia_level", "use_crs", "ignored"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must explain the combination (missing %q): %v", want, err)
		}
	}
}

// With the WAF switched off entirely its subtree is inert by an explicit,
// visible choice — not the silent kind of dead setting this guards against, so
// it must not block startup.
func TestValidateWAF_DisabledWAFIgnoresItsKnobs(t *testing.T) {
	cfg := validBase()
	cfg.Security.WAF = WAFConfig{Enabled: false, UseCRS: false, ParanoiaLevel: 4, AnomalyThreshold: 9}
	if err := Validate(cfg); err != nil {
		t.Fatalf("a disabled WAF must not have its unused knobs rejected: %v", err)
	}
}

// The shipped configuration has to satisfy its own validator. It used to carry
// exactly the combination now rejected — use_crs: false with paranoia_level: 1
// and anomaly_threshold: 5 — which is what made the gap concrete rather than
// theoretical: the file the README tells operators to start from advertised two
// security knobs that did nothing.
func TestValidateWAF_ShippedConfigIsAccepted(t *testing.T) {
	cfg, err := Load("../../config/gateway.yaml")
	if err != nil {
		t.Fatalf("load shipped config: %v", err)
	}
	// Validate needs the secrets the shipped file deliberately leaves blank.
	t.Setenv("AEGIS_ADMIN_SECRET", "a-strong-admin-secret-32-characters!!")
	cfg.AdminSecret = os.Getenv("AEGIS_ADMIN_SECRET")
	cfg.Redis.Password = "redis-pass"
	if err := Validate(cfg); err != nil {
		t.Fatalf("the shipped config must pass its own validator: %v", err)
	}
}
