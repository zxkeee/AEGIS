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
	fwDORA  = "DORA"
	fwISO   = "ISO 27001:2022"
)

type controlRef struct {
	framework, control, title string
	// runtimeOnly marks a control that only an OBSERVED event can evidence.
	//
	// The distinction is the difference between a true and a false claim. A
	// catalog finding says "this endpoint could be abused"; a runtime abuse
	// event says "an attempt was detected and handled". DORA Art. 10 is about
	// detection mechanisms actually working — a static finding is evidence of
	// the opposite, if anything, and must not be counted toward it.
	runtimeOnly bool
}

// owaspControls maps an OWASP API category (e.g. "API1") to the framework
// controls it evidences. Keyed by the bare category (the ":2023" suffix stripped).
var owaspControls = map[string][]controlRef{
	"API1": { // Broken Object Level Authorization (BOLA / IDOR)
		{framework: fwOWASP, control: "API1:2023", title: "Broken Object Level Authorization"},
		{framework: fwNIS2, control: "Art. 21(2)(i)", title: "Access control policies"},
		{framework: fwDORA, control: "Art. 9(4)(c)", title: "Logical access limited to what is required"},
		{framework: fwDORA, control: "Art. 10(1)", title: "Prompt detection of anomalous activities", runtimeOnly: true},
		{framework: fwISO, control: "A.8.3", title: "Information access restriction"},
	},
	"API2": { // Broken Authentication
		{framework: fwOWASP, control: "API2:2023", title: "Broken Authentication"},
		{framework: fwNIS2, control: "Art. 21(2)(j)", title: "Multi-factor / continuous authentication"},
		{framework: fwDORA, control: "Art. 9(4)(d)", title: "Strong authentication mechanisms"},
		{framework: fwISO, control: "A.5.17", title: "Authentication information"},
	},
	"API3": { // Broken Object Property Level Authorization / excessive data exposure
		{framework: fwOWASP, control: "API3:2023", title: "Excessive data exposure"},
		{framework: fwNIS2, control: "Art. 21(2)(h)", title: "Cryptography and encryption of data"},
		{framework: fwDORA, control: "Art. 9(3)", title: "Confidentiality and integrity of data in transit"},
		{framework: fwISO, control: "A.5.34", title: "Privacy and protection of PII"},
	},
	"API5": { // Broken Function Level Authorization (BFLA)
		{framework: fwOWASP, control: "API5:2023", title: "Broken Function Level Authorization"},
		{framework: fwNIS2, control: "Art. 21(2)(i)", title: "Access control policies"},
		{framework: fwDORA, control: "Art. 9(4)(c)", title: "Logical access limited to what is required"},
		{framework: fwDORA, control: "Art. 10(1)", title: "Prompt detection of anomalous activities", runtimeOnly: true},
		{framework: fwISO, control: "A.8.2", title: "Privileged access rights"},
	},
	"API9": { // Improper Inventory Management (shadow / undocumented APIs)
		{framework: fwOWASP, control: "API9:2023", title: "Improper Inventory Management"},
		{framework: fwNIS2, control: "Art. 21(2)(i)", title: "Asset management"},
		{framework: fwDORA, control: "Art. 8(1)", title: "Identification and documentation of ICT assets"},
		{framework: fwISO, control: "A.5.9", title: "Inventory of information and associated assets"},
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
	// NotEvidenced names controls of this framework that AEGIS structurally
	// cannot speak to, with the reason. A report that lists only what it mapped
	// reads as covering the framework; these are the parts it does not.
	NotEvidenced []uncoveredControl `json:"not_evidenced,omitempty"`
}

// uncoveredControl is a control this product does not evidence, and why.
//
// It is deliberately a permanent, static statement rather than something
// derived from the data: the gap is in what the gateway observes, so it is
// there whether or not this particular report found anything. An auditor who
// discovers such a gap unaided stops trusting the whole document, so the
// document says it first.
type uncoveredControl struct {
	Control string `json:"control"`
	Title   string `json:"title"`
	Reason  string `json:"reason"`
}

// frameworkGaps is the honest half of the mapping.
//
// Every entry here is incident LIFECYCLE, and that is not an accident: AEGIS
// detects and records security events, but it has no incident entity. Events
// are never grouped into an incident, tracked through a lifecycle, classified
// against a regulator's criteria, or driven to a notification deadline. Those
// obligations are real and a buyer will ask about them, so the report names
// them as gaps rather than letting the mapped controls imply coverage.
var frameworkGaps = map[string][]uncoveredControl{
	fwDORA: {
		{"Art. 17", "ICT-related incident management process",
			"AEGIS records security events but has no incident entity: events are not grouped, tracked through a lifecycle, or assigned an owner."},
		{"Art. 18", "Classification of ICT-related incidents",
			"classification needs clients affected, duration, geographical spread, data losses and economic impact — none of which the gateway observes."},
		{"Art. 19", "Reporting of major incidents to the competent authority",
			"there is no notification workflow and no initial / intermediate / final report timeline."},
	},
	fwNIS2: {
		{"Art. 23", "Reporting obligations",
			"the 24h early warning / 72h notification / 1 month final report timeline is not tracked. AEGIS produces evidence such a report would cite, not the report itself."},
	},
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

	// observed says the evidence is a detected event rather than a static
	// finding. Controls marked runtimeOnly accept nothing else.
	add := func(cat, severity, issue string, observed bool) {
		for _, cr := range owaspControls[cat] {
			if cr.runtimeOnly && !observed {
				continue
			}
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
		add(cat, r.Finding.Severity, r.Finding.Title+" — "+r.Method+" "+r.PathTemplate, false)
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
		add(cat, "critical", "runtime: "+strings.ReplaceAll(reason, "_", " ")+" ("+strconv.Itoa(n)+" events)", true)
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
	// The two EU regulations sit together, after the technical taxonomy that
	// produced the finding and before the standard.
	for _, fw := range []string{fwOWASP, fwNIS2, fwDORA, fwISO} {
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
		rep.Frameworks = append(rep.Frameworks, complianceFramework{
			Framework: fw, Controls: cs, NotEvidenced: frameworkGaps[fw],
		})
	}
	return rep
}
