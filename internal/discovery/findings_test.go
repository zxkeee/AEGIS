package discovery

import (
	"strings"
	"testing"
)

func hasFinding(fs []Finding, code string) *Finding {
	for i := range fs {
		if fs[i].Code == code {
			return &fs[i]
		}
	}
	return nil
}

// PII + observed anonymous access = confirmed exposure (API3/API2), graded by
// the class of data that was exposed.
//
// The fixture now names the data type, because it decides the grade. It used to
// leave PIITypes empty and assert critical, which was true of every exposure
// then and is true of card data now — see
// TestDetectFindings_SeverityFollowsTheDataClass for the reasoning and
// demo/fp-assessment for the measurement that forced it.
func TestFindings_PIIWithAnon_Critical(t *testing.T) {
	e := Endpoint{PIICount: 5, AnonCount: 3, PIITypes: []string{"credit_card"}}
	fs := DetectFindings(e, Controls{AuthRequired: false}, true)
	f := hasFinding(fs, "sensitive_data_no_auth")
	if f == nil {
		t.Fatal("expected sensitive_data_no_auth finding")
	}
	if f.Severity != "critical" || f.OWASP != "API3:2023" {
		t.Fatalf("finding = %+v", f)
	}
}

// PII returned but auth not enforced and no anon observed yet = latent warning,
// not the confirmed-critical one.
func TestFindings_PIIAuthNotRequired_Warning(t *testing.T) {
	e := Endpoint{PIICount: 2, AnonCount: 0}
	fs := DetectFindings(e, Controls{AuthRequired: false}, true)
	if hasFinding(fs, "sensitive_data_no_auth") != nil {
		t.Fatal("must not raise the confirmed-critical finding without anon traffic")
	}
	f := hasFinding(fs, "sensitive_data_auth_not_required")
	if f == nil || f.Severity != "warning" {
		t.Fatalf("expected latent warning, got %+v", fs)
	}
}

// PII on a properly authenticated endpoint with no anon access = no finding.
func TestFindings_PIIWithAuth_None(t *testing.T) {
	e := Endpoint{PIICount: 9, AnonCount: 0}
	fs := DetectFindings(e, Controls{AuthRequired: true}, true)
	if len(fs) != 0 {
		t.Fatalf("authenticated PII endpoint must have no findings, got %+v", fs)
	}
}

// No PII = no data-exposure findings regardless of auth.
func TestFindings_NoPII_None(t *testing.T) {
	e := Endpoint{PIICount: 0, AnonCount: 100}
	if fs := DetectFindings(e, Controls{AuthRequired: false}, true); len(fs) != 0 {
		t.Fatalf("no PII must yield no findings, got %+v", fs)
	}
}

// Findings name the compliance category when data types are classified, so an
// operator sees "PCI (credit_card)" rather than a generic "PII".
func TestFindings_NamesComplianceCategory(t *testing.T) {
	e := Endpoint{PIICount: 3, AnonCount: 2, PIITypes: []string{"credit_card", "email"}}
	fs := DetectFindings(e, Controls{AuthRequired: false}, true)
	f := hasFinding(fs, "sensitive_data_no_auth")
	if f == nil {
		t.Fatal("expected exposure finding")
	}
	if !strings.Contains(f.Why, "PCI") || !strings.Contains(f.Why, "credit_card") {
		t.Fatalf("why should name PCI/credit_card, got %q", f.Why)
	}
}

func TestDataLabel(t *testing.T) {
	if got := dataLabel([]string{"credit_card"}); !strings.HasPrefix(got, "PCI") {
		t.Fatalf("dataLabel card = %q", got)
	}
	if got := dataLabel(nil); got != "sensitive data" {
		t.Fatalf("dataLabel nil = %q", got)
	}
	if got := dataLabel([]string{"custom_thing"}); !strings.Contains(got, "sensitive data") {
		t.Fatalf("unknown type label = %q", got)
	}
}

// Shadow endpoint serving PII raises the dedicated shadow finding too.
func TestFindings_ShadowWithPII(t *testing.T) {
	e := Endpoint{PIICount: 4, AnonCount: 1}
	fs := DetectFindings(e, Controls{AuthRequired: false}, false /* unmatched = shadow */)
	if hasFinding(fs, "shadow_sensitive_data") == nil {
		t.Fatalf("expected shadow_sensitive_data finding, got %+v", fs)
	}
	if hasFinding(fs, "sensitive_data_no_auth") == nil {
		t.Fatal("shadow endpoint should still raise the data-exposure finding")
	}
}

// "We saw no evidence" and "we kept no evidence" are opposite statements that an
// empty result cannot tell apart. Every finding must therefore say which one it
// is: an auditor asking "show me the requests behind this" needs to be told
// plainly when the answer is that they were counted and never retained.
func TestDetectFindings_DeclareTheirEvidenceProvenance(t *testing.T) {
	cases := []struct {
		name    string
		ep      Endpoint
		ctrl    Controls
		matched bool
	}{
		{"confirmed exposure", Endpoint{PIICount: 5, AnonCount: 2, PIITypes: []string{"credit_card"}}, Controls{AuthRequired: true}, true},
		{"latent exposure", Endpoint{PIICount: 5, PIITypes: []string{"ssn"}}, Controls{AuthRequired: false}, true},
		{"shadow endpoint", Endpoint{PIICount: 3, PIITypes: []string{"email"}}, Controls{AuthRequired: true}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			found := DetectFindings(c.ep, c.ctrl, c.matched)
			if len(found) == 0 {
				t.Fatal("no finding produced; fixture no longer exercises the path")
			}
			for _, f := range found {
				if f.Evidence.Kind == "" {
					t.Errorf("%s: evidence kind is empty — a reader cannot tell recorded from tallied", f.Code)
				}
				// These are all counter-derived today. The point of saying so is
				// that the absence is stated rather than implied by an empty list.
				if f.Evidence.Kind != EvidenceCounters {
					t.Errorf("%s: kind = %q, want %q", f.Code, f.Evidence.Kind, EvidenceCounters)
				}
				if f.Evidence.Note == "" {
					t.Errorf("%s: counter-derived finding gives no reason for having no events", f.Code)
				}
				if len(f.Evidence.Reasons) != 0 {
					t.Errorf("%s: counter-derived finding must not point at forensic reasons it does not have", f.Code)
				}
			}
		})
	}
}

// Severity follows what was exposed, not merely that something was.
//
// Measured against a real third-party API (demo/fp-assessment, Codeberg), the
// old constant produced ten critical findings, every one of them "this endpoint
// returns committer email addresses to anonymous callers" — on a public code
// host, where those addresses are in the commit objects by design.
//
// A grade that is wrong in the alarming direction is not the safe choice: ten
// criticals that are all the same benign fact teach an operator to skim, and
// the eleventh is a card number.
func TestDetectFindings_SeverityFollowsTheDataClass(t *testing.T) {
	base := Endpoint{
		ID: "GET:/x", Method: "GET", PathTemplate: "/x",
		RequestCount: 10, PIICount: 10, AnonCount: 10,
	}

	cases := []struct {
		name     string
		types    []string
		want     string
		because  string
	}{
		{"email alone", []string{"email"}, "warning",
			"a public profile or a commit author is frequently deliberate"},
		{"phone alone", []string{"phone"}, "warning", "same"},
		{"card", []string{"credit_card"}, "critical",
			"there is no ordinary reason to serve a card number to an anonymous caller"},
		{"health identifier", []string{"npi"}, "critical", "PHI carries its own regime"},
		{"card mixed with email", []string{"email", "credit_card"}, "critical",
			"a mixture grades by its worst class"},
		{"ssn", []string{"ssn"}, "warning",
			"ssn is classified PII by internal/classify; if that changes, this " +
				"expectation changes with it"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := base
			e.PIITypes = c.types
			got := DetectFindings(e, Controls{}, true)

			var found *Finding
			for i := range got {
				if got[i].Code == "sensitive_data_no_auth" {
					found = &got[i]
					break
				}
			}
			if found == nil {
				t.Fatalf("no sensitive_data_no_auth finding for %v — the detection "+
					"itself must not change, only its grade", c.types)
			}
			if found.Severity != c.want {
				t.Errorf("severity = %q, want %q (%s)", found.Severity, c.want, c.because)
			}
		})
	}
}

// The finding must still fire for every class: grading is not filtering. An
// exposure that is merely a warning is still an exposure, and an operator who
// decides it is deliberate should make that decision from a list, not from
// silence.
func TestDetectFindings_GradingDoesNotSuppress(t *testing.T) {
	e := Endpoint{
		ID: "GET:/x", Method: "GET", PathTemplate: "/x",
		RequestCount: 5, PIICount: 5, AnonCount: 5, PIITypes: []string{"email"},
	}
	got := DetectFindings(e, Controls{}, true)
	var codes []string
	for _, f := range got {
		codes = append(codes, f.Code)
	}
	if len(got) == 0 {
		t.Fatalf("an email exposure produced no finding at all; codes=%v", codes)
	}
}
