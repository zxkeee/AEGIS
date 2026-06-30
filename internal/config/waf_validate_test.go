package config

import "testing"

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
			cfg := GatewayConfig{Security: SecurityConfig{WAF: WAFConfig{
				Enabled: true, CRSEnabled: c.crs, ParanoiaLevel: c.pl,
			}}}
			err := validateWAF(cfg)
			if (err != nil) != c.wantErr {
				t.Errorf("validateWAF err=%v, wantErr=%v", err, c.wantErr)
			}
		})
	}
}
