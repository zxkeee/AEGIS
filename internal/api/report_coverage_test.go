package api

import (
	"context"
	"strings"
	"testing"

	"api-gateway/internal/discovery"
	"api-gateway/internal/logger"
)

// finding builds an endpoint carrying one finding of the given evidence kind.
func endpointWithFinding(kind string) discovery.Endpoint {
	return discovery.Endpoint{
		Method: "GET", PathTemplate: "/orders/{id}",
		Findings: []discovery.Finding{{
			Code: "sensitive_data_no_auth", Severity: "critical",
			Evidence: discovery.EvidenceRef{Kind: kind},
		}},
	}
}

// containsPhrase reports whether any limit mentions the phrase.
func containsPhrase(limits []string, phrase string) bool {
	for _, l := range limits {
		if strings.Contains(l, phrase) {
			return true
		}
	}
	return false
}

func limitsOf(t *testing.T, cov map[string]any) []string {
	t.Helper()
	l, ok := cov["limits"].([]string)
	if !ok {
		t.Fatalf("coverage has no limits list: %v", cov)
	}
	return l
}

// A report that lists only what it found reads as complete. This one is not:
// it sees the traffic routed through the gateway and nothing else. Saying so is
// the difference between a document an auditor can rely on and one they stop
// trusting the moment they find an endpoint it never saw.
func TestReportCoverage_AlwaysStatesWhatItCannotSee(t *testing.T) {
	h := &handlers{log: logger.New("error")}
	cov := h.reportCoverage(context.Background(), 0, nil)
	limits := limitsOf(t, cov)
	if !containsPhrase(limits, "routed through this gateway") {
		t.Fatalf("no statement about traffic outside the gateway: %v", limits)
	}
}

// The most consequential admission: how much of the finding set cannot be
// evidenced request by request. An auditor asking "show me" needs this number
// before they ask, not after.
func TestReportCoverage_CountsFindingsThatCannotBeEvidenced(t *testing.T) {
	h := &handlers{log: logger.New("error")}
	eps := []discovery.Endpoint{
		endpointWithFinding(discovery.EvidenceCounters),
		endpointWithFinding(discovery.EvidenceCounters),
		endpointWithFinding(discovery.EvidenceEvents),
	}
	cov := h.reportCoverage(context.Background(), len(eps), eps)

	if cov["findings_from_counters_only"] != 2 {
		t.Errorf("counters-only = %v, want 2", cov["findings_from_counters_only"])
	}
	if cov["findings_with_event_evidence"] != 1 {
		t.Errorf("event-backed = %v, want 1", cov["findings_with_event_evidence"])
	}
	if !containsPhrase(limitsOf(t, cov), "cannot be produced on request") {
		t.Errorf("the limitation is counted but not stated in words: %v", cov["limits"])
	}
}

// With every finding event-backed there is nothing to admit on that front, and
// the report must not manufacture a caveat it does not have.
func TestReportCoverage_SilentWhenEverythingIsEvidenced(t *testing.T) {
	h := &handlers{log: logger.New("error")}
	eps := []discovery.Endpoint{endpointWithFinding(discovery.EvidenceEvents)}
	cov := h.reportCoverage(context.Background(), len(eps), eps)
	if containsPhrase(limitsOf(t, cov), "derived from counters") {
		t.Errorf("claimed a counters-only gap that does not exist: %v", cov["limits"])
	}
}

// Without a durable store the security record is a capped in-memory ring. A
// report built on it must say so rather than present it as the record.
func TestReportCoverage_FlagsTheMissingDurableStore(t *testing.T) {
	h := &handlers{log: logger.New("error")}
	cov := h.reportCoverage(context.Background(), 0, nil)
	if cov["evidence_store"] != sourceRing {
		t.Errorf("evidence_store = %v, want %q", cov["evidence_store"], sourceRing)
	}
	if !containsPhrase(limitsOf(t, cov), "capped in-memory ring") {
		t.Errorf("the missing durable store is not stated: %v", cov["limits"])
	}
}

// Hitting the endpoint cap is itself a coverage fact: the list is short because
// it was cut, not because that is all there is.
func TestReportCoverage_AdmitsTruncation(t *testing.T) {
	h := &handlers{log: logger.New("error")}
	cov := h.reportCoverage(context.Background(), reportEndpointLimit, nil)
	if !containsPhrase(limitsOf(t, cov), "truncated") {
		t.Errorf("a truncated list did not say so: %v", cov["limits"])
	}

	// A short list must not carry the truncation caveat.
	cov = h.reportCoverage(context.Background(), 3, nil)
	if containsPhrase(limitsOf(t, cov), "truncated") {
		t.Errorf("a complete list claimed truncation: %v", cov["limits"])
	}
}
