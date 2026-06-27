package api

import (
	"strings"
	"testing"
)

func TestSanitizeMetricName(t *testing.T) {
	cases := map[string]string{
		"requests_total":   "requests_total",
		"bola.detected":    "bola_detected",
		"waf:blocked-reqs": "waf_blocked_reqs",
		"abuse/bfla":       "abuse_bfla",
		"UPPER_lower_123":  "UPPER_lower_123",
		"":                 "",
	}
	for in, want := range cases {
		if got := sanitizeMetricName(in); got != want {
			t.Errorf("sanitizeMetricName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderProm_FormatAndOrdering(t *testing.T) {
	out := renderProm(map[string]int64{
		"zeta_total":  3,
		"alpha.count": 7,
	})

	// Sorted: alpha before zeta.
	if i, j := strings.Index(out, "aegis_alpha_count"), strings.Index(out, "aegis_zeta_total"); i < 0 || j < 0 || i > j {
		t.Fatalf("metrics not sorted/rendered:\n%s", out)
	}
	for _, want := range []string{
		"# TYPE aegis_alpha_count counter",
		"aegis_alpha_count 7",
		"aegis_zeta_total 3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderProm_Empty(t *testing.T) {
	if got := renderProm(map[string]int64{}); got != "" {
		t.Errorf("expected empty output, got %q", got)
	}
}
