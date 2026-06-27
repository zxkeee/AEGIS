package api

import (
	"testing"

	"api-gateway/internal/discovery"
)

// flattenFindings must sort critical-first and count by severity.
func TestFlattenFindings_SortsAndCounts(t *testing.T) {
	eps := []discovery.Endpoint{
		{Method: "GET", PathTemplate: "/a", Findings: []discovery.Finding{
			{Code: "x", Severity: "warning"},
		}},
		{Method: "GET", PathTemplate: "/b", Findings: []discovery.Finding{
			{Code: "y", Severity: "critical"},
			{Code: "z", Severity: "info"},
		}},
		{Method: "GET", PathTemplate: "/c"}, // no findings
	}
	rows, counts := flattenFindings(eps)
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	if rows[0].Finding.Severity != "critical" {
		t.Fatalf("critical must sort first, got %q", rows[0].Finding.Severity)
	}
	if rows[len(rows)-1].Finding.Severity != "info" {
		t.Fatalf("info must sort last, got %q", rows[len(rows)-1].Finding.Severity)
	}
	if counts["critical"] != 1 || counts["warning"] != 1 || counts["info"] != 1 {
		t.Fatalf("counts = %v", counts)
	}
}

func TestFlattenFindings_Empty(t *testing.T) {
	rows, counts := flattenFindings(nil)
	if len(rows) != 0 || counts["critical"] != 0 {
		t.Fatalf("empty = %v %v", rows, counts)
	}
}
