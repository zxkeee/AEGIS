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

	rep := buildCompliance(rows, abuse)

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

	dora := frameworkByName(t, buildCompliance(rows, abuse), fwDORA)
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
		dora := frameworkByName(t, buildCompliance(static, nil), fwDORA)
		if c, ok := controlByID(dora, "Art. 10(1)"); ok {
			t.Fatalf("a static finding evidenced the detection control: %+v", c)
		}
		// The access-control article must still be there — only detection is gated.
		if _, ok := controlByID(dora, "Art. 9(4)(c)"); !ok {
			t.Error("Art. 9(4)(c) should be evidenced by an access-control finding")
		}
	})

	t.Run("with an observed event", func(t *testing.T) {
		dora := frameworkByName(t, buildCompliance(static, map[string]int{"bola_object_ownership": 2}), fwDORA)
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
	}, map[string]int{"bola_object_ownership": 1})

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
