package api

import (
	"sort"
	"strconv"
	"strings"
)

// Compliance mapping: AEGIS's API-security findings, expressed in the language of
// the frameworks a buyer/auditor cares about. Each OWASP API risk maps to the
// relevant NIS2 (Directive (EU) 2022/2555, Art. 21(2)) and ISO/IEC 27001:2022
// Annex A controls, so a finding like "IDOR on /orders/{id}" surfaces as a
// concrete access-control gap under NIS2 and ISO. This is a mapping aid, not
// legal certification.

const (
	fwOWASP = "OWASP API Top 10"
	fwNIS2  = "NIS2"
	fwISO   = "ISO 27001:2022"
)

type controlRef struct{ framework, control, title string }

// owaspControls maps an OWASP API category (e.g. "API1") to the framework
// controls it evidences. Keyed by the bare category (the ":2023" suffix stripped).
var owaspControls = map[string][]controlRef{
	"API1": { // Broken Object Level Authorization (BOLA / IDOR)
		{fwOWASP, "API1:2023", "Broken Object Level Authorization"},
		{fwNIS2, "Art. 21(2)(i)", "Access control policies"},
		{fwISO, "A.8.3", "Information access restriction"},
	},
	"API2": { // Broken Authentication
		{fwOWASP, "API2:2023", "Broken Authentication"},
		{fwNIS2, "Art. 21(2)(j)", "Multi-factor / continuous authentication"},
		{fwISO, "A.5.17", "Authentication information"},
	},
	"API3": { // Broken Object Property Level Authorization / excessive data exposure
		{fwOWASP, "API3:2023", "Excessive data exposure"},
		{fwNIS2, "Art. 21(2)(h)", "Cryptography and encryption of data"},
		{fwISO, "A.5.34", "Privacy and protection of PII"},
	},
	"API5": { // Broken Function Level Authorization (BFLA)
		{fwOWASP, "API5:2023", "Broken Function Level Authorization"},
		{fwNIS2, "Art. 21(2)(i)", "Access control policies"},
		{fwISO, "A.8.2", "Privileged access rights"},
	},
	"API9": { // Improper Inventory Management (shadow / undocumented APIs)
		{fwOWASP, "API9:2023", "Improper Inventory Management"},
		{fwNIS2, "Art. 21(2)(i)", "Asset management"},
		{fwISO, "A.5.9", "Inventory of information and associated assets"},
	},
}

// abuseOWASP maps a runtime abuse reason to its OWASP API category.
func abuseOWASP(reason string) string {
	switch {
	case strings.HasPrefix(reason, "bola"):
		return "API1"
	case strings.HasPrefix(reason, "bfla"):
		return "API5"
	default:
		return ""
	}
}

type complianceControl struct {
	Framework string   `json:"framework"`
	Control   string   `json:"control"`
	Title     string   `json:"title"`
	Severity  string   `json:"severity"` // max severity of the mapped issues
	Count     int      `json:"count"`
	Issues    []string `json:"issues"`
}

type complianceFramework struct {
	Framework string              `json:"framework"`
	Controls  []complianceControl `json:"controls"`
}

// evidenceProvenance states where a report's runtime numbers came from and what
// period they cover. Without it a report reads as complete regardless of whether
// it was built from the durable record or from a capped in-memory buffer.
type evidenceProvenance struct {
	Source   string `json:"source"`
	Complete bool   `json:"complete"`
	From     any    `json:"from"`
	To       any    `json:"to"`
	Note     string `json:"note,omitempty"`
}

type complianceReport struct {
	Evidence   evidenceProvenance    `json:"evidence"`
	Frameworks []complianceFramework `json:"frameworks"`
	Summary    struct {
		Critical         int `json:"critical"`
		Warning          int `json:"warning"`
		ControlsAffected int `json:"controls_affected"`
	} `json:"summary"`
}

const maxIssuesPerControl = 8

func severityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "warning":
		return 1
	default:
		return 2
	}
}

// buildCompliance maps catalog findings and runtime abuse counts onto the
// framework controls they evidence, grouped by framework. Pure function so the
// mapping is unit-testable without a database.
func buildCompliance(rows []findingRow, abuse map[string]int) complianceReport {
	type key struct{ framework, control string }
	agg := map[key]*complianceControl{}
	var rep complianceReport

	add := func(cat, severity, issue string) {
		for _, cr := range owaspControls[cat] {
			k := key{cr.framework, cr.control}
			c := agg[k]
			if c == nil {
				c = &complianceControl{Framework: cr.framework, Control: cr.control, Title: cr.title, Severity: severity}
				agg[k] = c
			}
			c.Count++
			if severityRank(severity) < severityRank(c.Severity) {
				c.Severity = severity
			}
			if len(c.Issues) < maxIssuesPerControl {
				c.Issues = append(c.Issues, issue)
			}
		}
	}

	for _, r := range rows {
		cat := strings.SplitN(r.Finding.OWASP, ":", 2)[0]
		if _, ok := owaspControls[cat]; !ok {
			continue
		}
		add(cat, r.Finding.Severity, r.Finding.Title+" — "+r.Method+" "+r.PathTemplate)
		switch r.Finding.Severity {
		case "critical":
			rep.Summary.Critical++
		case "warning":
			rep.Summary.Warning++
		}
	}

	for reason, n := range abuse {
		if n <= 0 {
			continue
		}
		cat := abuseOWASP(reason)
		if cat == "" {
			continue
		}
		add(cat, "critical", "runtime: "+strings.ReplaceAll(reason, "_", " ")+" ("+strconv.Itoa(n)+" events)")
		rep.Summary.Critical += n
	}

	// Group controls by framework, ordered OWASP → NIS2 → ISO, controls by
	// severity then id.
	byFw := map[string][]complianceControl{}
	for _, c := range agg {
		byFw[c.Framework] = append(byFw[c.Framework], *c)
	}
	rep.Summary.ControlsAffected = len(agg)
	rep.Frameworks = []complianceFramework{}
	for _, fw := range []string{fwOWASP, fwNIS2, fwISO} {
		cs := byFw[fw]
		if len(cs) == 0 {
			continue
		}
		sort.SliceStable(cs, func(i, j int) bool {
			if severityRank(cs[i].Severity) != severityRank(cs[j].Severity) {
				return severityRank(cs[i].Severity) < severityRank(cs[j].Severity)
			}
			return cs[i].Control < cs[j].Control
		})
		rep.Frameworks = append(rep.Frameworks, complianceFramework{Framework: fw, Controls: cs})
	}
	return rep
}
