package api

import (
	"strings"
	"testing"

	"api-gateway/internal/discovery"
)

func fr(owasp, sev, title, method, path string) findingRow {
	return findingRow{Method: method, PathTemplate: path, Finding: discovery.Finding{OWASP: owasp, Severity: sev, Title: title}}
}

func TestBuildCompliance(t *testing.T) {
	rows := []findingRow{
		fr("API3:2023", "critical", "Sensitive data exposed to unauthenticated callers", "GET", "/users/{id}"),
		fr("API9:2023", "critical", "Shadow endpoint serving sensitive data", "GET", "/legacy/{id}"),
	}
	abuse := map[string]int{"bola_object_ownership": 3, "bfla_privileged_access": 1, "waf_blocked": 9}

	rep := buildCompliance(rows, abuse, incidentEvidence{})

	// Frameworks present and ordered OWASP → NIS2 → DORA → ISO.
	if len(rep.Frameworks) != 4 {
		t.Fatalf("frameworks = %d, want 4 (%+v)", len(rep.Frameworks), rep.Frameworks)
	}
	order := []string{fwOWASP, fwNIS2, fwDORA, fwISO}
	for i, want := range order {
		if rep.Frameworks[i].Framework != want {
			t.Fatalf("framework[%d] = %s, want %s", i, rep.Frameworks[i].Framework, want)
		}
	}

	// NIS2 must carry an access-control control (from BOLA/BFLA/API-mappings).
	var nis2Access bool
	for _, c := range frameworkByName(t, rep, fwNIS2).Controls {
		if c.Control == "Art. 21(2)(i)" {
			nis2Access = true
		}
	}
	if !nis2Access {
		t.Fatal("NIS2 Art. 21(2)(i) access control not mapped")
	}

	// waf_blocked is not an access-control abuse → must not inflate the report.
	// Summary critical = 2 findings + 3 (bola) + 1 (bfla) = 6.
	if rep.Summary.Critical != 6 {
		t.Fatalf("summary critical = %d, want 6", rep.Summary.Critical)
	}
	if rep.Summary.ControlsAffected == 0 {
		t.Fatal("no controls affected")
	}
}

// frameworkByName finds one framework section, so tests do not break on order.
func frameworkByName(t *testing.T, rep complianceReport, name string) complianceFramework {
	t.Helper()
	for _, fw := range rep.Frameworks {
		if fw.Framework == name {
			return fw
		}
	}
	t.Fatalf("framework %s missing from the report", name)
	return complianceFramework{}
}

func controlByID(fw complianceFramework, id string) (complianceControl, bool) {
	for _, c := range fw.Controls {
		if c.Control == id {
			return c, true
		}
	}
	return complianceControl{}, false
}

// DORA is the framework a financial-sector buyer asks about by name. Each
// article must be reachable from the findings that actually evidence it.
func TestBuildCompliance_DORAArticles(t *testing.T) {
	rows := []findingRow{
		fr("API3:2023", "critical", "Sensitive data exposed to unauthenticated callers", "GET", "/users/{id}"),
		fr("API9:2023", "critical", "Shadow endpoint serving sensitive data", "GET", "/legacy/{id}"),
		fr("API2:2023", "warning", "Weak authentication", "POST", "/login"),
	}
	abuse := map[string]int{"bola_object_ownership": 3, "bfla_privileged_access": 1}

	dora := frameworkByName(t, buildCompliance(rows, abuse, incidentEvidence{}), fwDORA)
	for _, want := range []string{
		"Art. 8(1)",    // asset identification ← shadow endpoint
		"Art. 9(3)",    // data confidentiality ← PII exposure
		"Art. 9(4)(c)", // logical access      ← BOLA/BFLA
		"Art. 9(4)(d)", // strong auth         ← broken authentication
		"Art. 10(1)",   // detection           ← observed abuse
	} {
		if _, ok := controlByID(dora, want); !ok {
			t.Errorf("DORA %s is not evidenced by any finding: %+v", want, dora.Controls)
		}
	}
}

// The distinction that keeps the mapping truthful. DORA Art. 10 is about
// detection mechanisms actually working. A catalog finding says an endpoint
// COULD be abused — that is not evidence a detection fired, and counting it
// would state something false to a regulator.
func TestBuildCompliance_DetectionControlNeedsAnObservedEvent(t *testing.T) {
	static := []findingRow{
		fr("API3:2023", "critical", "Sensitive data exposed to unauthenticated callers", "GET", "/users/{id}"),
		// An API1 finding is the strongest static case there is, and still must
		// not evidence detection.
		fr("API1:2023", "critical", "Object identifier accepted without ownership check", "GET", "/orders/{id}"),
	}

	t.Run("static findings alone", func(t *testing.T) {
		dora := frameworkByName(t, buildCompliance(static, nil, incidentEvidence{}), fwDORA)
		if c, ok := controlByID(dora, "Art. 10(1)"); ok {
			t.Fatalf("a static finding evidenced the detection control: %+v", c)
		}
		// The access-control article must still be there — only detection is gated.
		if _, ok := controlByID(dora, "Art. 9(4)(c)"); !ok {
			t.Error("Art. 9(4)(c) should be evidenced by an access-control finding")
		}
	})

	t.Run("with an observed event", func(t *testing.T) {
		dora := frameworkByName(t, buildCompliance(static, map[string]int{"bola_object_ownership": 2}, incidentEvidence{}), fwDORA)
		c, ok := controlByID(dora, "Art. 10(1)")
		if !ok {
			t.Fatal("an observed abuse event did not evidence the detection control")
		}
		if c.Count != 1 {
			t.Errorf("count = %d, want 1 — only the observed event may count", c.Count)
		}
		for _, issue := range c.Issues {
			if !strings.HasPrefix(issue, "runtime:") {
				t.Errorf("detection control cites a non-runtime issue: %q", issue)
			}
		}
	})
}

// A report that lists only what it mapped reads as covering the framework. The
// incident-lifecycle articles are the ones a buyer will ask about and the ones
// AEGIS has no answer for, so the document must say so itself.
func TestBuildCompliance_NamesTheArticlesItCannotEvidence(t *testing.T) {
	rep := buildCompliance([]findingRow{
		fr("API3:2023", "critical", "Sensitive data exposed to unauthenticated callers", "GET", "/users/{id}"),
	}, map[string]int{"bola_object_ownership": 1}, incidentEvidence{})

	for _, tc := range []struct {
		framework string
		articles  []string
	}{
		{fwDORA, []string{"Art. 17", "Art. 18", "Art. 19"}},
		{fwNIS2, []string{"Art. 23"}},
	} {
		fw := frameworkByName(t, rep, tc.framework)
		if len(fw.NotEvidenced) != len(tc.articles) {
			t.Errorf("%s: not_evidenced = %d entries, want %d", tc.framework, len(fw.NotEvidenced), len(tc.articles))
		}
		for _, art := range tc.articles {
			var found bool
			for _, u := range fw.NotEvidenced {
				if u.Control == art {
					found = true
					if u.Reason == "" || u.Title == "" {
						t.Errorf("%s %s: an uncovered control without a reason tells a reader nothing", tc.framework, art)
					}
				}
			}
			if !found {
				t.Errorf("%s does not admit it cannot evidence %s: %+v", tc.framework, art, fw.NotEvidenced)
			}
		}
		// An article that is admitted as unevidenced must not also appear as a
		// mapped control — the report would be contradicting itself.
		for _, u := range fw.NotEvidenced {
			if c, ok := controlByID(fw, u.Control); ok {
				t.Errorf("%s %s is listed both as evidenced (%+v) and as not evidenced", tc.framework, u.Control, c)
			}
		}
	}
}

// The incident articles must move out of "not evidenced" only when the record
// actually supports them — and each one has its own bar. Recording incidents is
// not classifying them, and classifying them is not reporting them.
func TestBuildCompliance_IncidentArticlesEarnTheirPlace(t *testing.T) {
	rows := []findingRow{fr("API3:2023", "critical", "PII exposed", "GET", "/users/{id}")}

	cases := []struct {
		name          string
		ev            incidentEvidence
		wantEvidenced []string
		wantGaps      []string
	}{
		{
			name:     "nothing recorded",
			ev:       incidentEvidence{},
			wantGaps: []string{"Art. 17", "Art. 18", "Art. 19"},
		},
		{
			name:          "incidents tracked but never classified or reported",
			ev:            incidentEvidence{Total: 4, Open: 3, Closed: 1},
			wantEvidenced: []string{"Art. 17"},
			wantGaps:      []string{"Art. 18", "Art. 19"},
		},
		{
			name:          "classified but not reported",
			ev:            incidentEvidence{Total: 4, Closed: 4, Classified: 2},
			wantEvidenced: []string{"Art. 17", "Art. 18"},
			wantGaps:      []string{"Art. 19"},
		},
		{
			name:          "reported",
			ev:            incidentEvidence{Total: 4, Closed: 4, Classified: 4, Notified: 3},
			wantEvidenced: []string{"Art. 17", "Art. 18", "Art. 19"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dora := frameworkByName(t, buildCompliance(rows, nil, tc.ev), fwDORA)
			for _, art := range tc.wantEvidenced {
				c, ok := controlByID(dora, art)
				if !ok {
					t.Errorf("%s is not evidenced", art)
					continue
				}
				if len(c.Issues) == 0 {
					t.Errorf("%s is evidenced but cites nothing", art)
				}
			}
			for _, art := range tc.wantGaps {
				if c, ok := controlByID(dora, art); ok {
					t.Errorf("%s is claimed as evidenced by %+v", art, c)
				}
				var admitted bool
				for _, u := range dora.NotEvidenced {
					if u.Control == art {
						admitted = true
						if u.Reason == "" {
							t.Errorf("%s is listed as a gap with no reason", art)
						}
					}
				}
				if !admitted {
					t.Errorf("%s is neither evidenced nor admitted as a gap", art)
				}
			}
		})
	}
}

// NIS2 Art. 23 is the same obligation in the other regulation, and it turns on
// the same fact: something was actually submitted.
func TestBuildCompliance_NIS2ReportingFollowsSubmissions(t *testing.T) {
	rows := []findingRow{fr("API3:2023", "critical", "PII exposed", "GET", "/users/{id}")}

	tracked := frameworkByName(t, buildCompliance(rows, nil, incidentEvidence{Total: 2, Classified: 2}), fwNIS2)
	if _, ok := controlByID(tracked, "Art. 23"); ok {
		t.Error("Art. 23 claimed as evidenced with no submission recorded — tracking is not reporting")
	}

	reported := frameworkByName(t, buildCompliance(rows, nil, incidentEvidence{Total: 2, Notified: 2}), fwNIS2)
	if _, ok := controlByID(reported, "Art. 23"); !ok {
		t.Error("Art. 23 is not evidenced despite a recorded submission")
	}
}

// A missed deadline is a breach of the obligation itself, whatever the incident
// turned out to be. It must be reported as critical, not buried.
func TestBuildCompliance_AnUnmetDeadlineIsCritical(t *testing.T) {
	rows := []findingRow{fr("API3:2023", "warning", "PII exposed", "GET", "/users/{id}")}
	ev := incidentEvidence{Total: 5, Classified: 5, Notified: 5, Overdue: 2}

	rep := buildCompliance(rows, nil, ev)
	c, ok := controlByID(frameworkByName(t, rep, fwDORA), "Art. 17")
	if !ok {
		t.Fatal("Art. 17 missing")
	}
	if c.Severity != "critical" {
		t.Errorf("severity = %s, want critical when a reporting deadline passed unmet", c.Severity)
	}
	var mentioned bool
	for _, iss := range c.Issues {
		if strings.Contains(iss, "deadline") {
			mentioned = true
		}
	}
	if !mentioned {
		t.Errorf("the overdue deadlines are not stated in the issues: %v", c.Issues)
	}
	if rep.Summary.Critical < ev.Overdue {
		t.Errorf("summary critical = %d, want at least the %d overdue obligations counted",
			rep.Summary.Critical, ev.Overdue)
	}
}

// With no findings at all there are no frameworks — except the ones that exist
// only to admit a gap. Dropping them would make the admission vanish exactly
// when there is nothing else to balance it.
func TestBuildCompliance_GapsSurviveAnEmptyReport(t *testing.T) {
	rep := buildCompliance(nil, nil, incidentEvidence{})

	dora := frameworkByName(t, rep, fwDORA)
	if len(dora.Controls) != 0 {
		t.Errorf("DORA has %d controls in an empty report", len(dora.Controls))
	}
	if len(dora.NotEvidenced) != 3 {
		t.Fatalf("DORA admits %d gaps in an empty report, want 3", len(dora.NotEvidenced))
	}
	if len(frameworkByName(t, rep, fwNIS2).NotEvidenced) != 1 {
		t.Error("NIS2 does not admit its reporting gap in an empty report")
	}
}

// A compliance report is judged partly on how carefully it was made. "1
// incidents" in a document going to a regulator undermines the rest of it.
func TestBuildCompliance_IncidentEvidenceReadsAsEnglish(t *testing.T) {
	rep := buildCompliance(nil, nil, incidentEvidence{Total: 1, Open: 1, Notified: 1, Classified: 1})
	dora := frameworkByName(t, rep, fwDORA)
	for _, art := range []string{"Art. 17", "Art. 18", "Art. 19"} {
		c, ok := controlByID(dora, art)
		if !ok {
			t.Fatalf("%s missing", art)
		}
		for _, iss := range c.Issues {
			if strings.Contains(iss, "1 incidents") {
				t.Errorf("%s: %q", art, iss)
			}
		}
	}

	// And the lifecycle counts must distinguish contained from open, because
	// that distinction is what Art. 17 is actually about.
	c, _ := controlByID(frameworkByName(t,
		buildCompliance(nil, nil, incidentEvidence{Total: 3, Open: 1, Contained: 1, Closed: 1}), fwDORA), "Art. 17")
	if !strings.Contains(c.Issues[0], "1 open, 1 contained, 1 closed") {
		t.Errorf("lifecycle counts = %q, want open/contained/closed stated separately", c.Issues[0])
	}
}
