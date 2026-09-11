package api

import (
	"fmt"
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
//
// A control referenced from more than one category MUST carry the same title in
// every reference. buildCompliance aggregates by {framework, control} and keeps
// whichever title it saw first, so two titles for one control means the report
// — which is signed — depends on the order rows came back from the database.
// NIS2 Art. 21(2)(i) shipped that way: "Access control policies" under API1/API5
// and "Asset management" under API9. Both are real parts of that article, which
// covers human resources security, access control policies and asset management;
// neither was the whole of it, and which one an auditor saw was a coin flip.
// TestOwaspControls_OneControlHasOneTitle enforces this.
var owaspControls = map[string][]controlRef{
	"API1": { // Broken Object Level Authorization (BOLA / IDOR)
		{framework: fwOWASP, control: "API1:2023", title: "Broken Object Level Authorization"},
		{framework: fwNIS2, control: "Art. 21(2)(i)", title: "Human resources security, access control policies and asset management"},
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
		{framework: fwNIS2, control: "Art. 21(2)(i)", title: "Human resources security, access control policies and asset management"},
		{framework: fwDORA, control: "Art. 9(4)(c)", title: "Logical access limited to what is required"},
		{framework: fwDORA, control: "Art. 10(1)", title: "Prompt detection of anomalous activities", runtimeOnly: true},
		{framework: fwISO, control: "A.8.2", title: "Privileged access rights"},
	},
	"API9": { // Improper Inventory Management (shadow / undocumented APIs)
		{framework: fwOWASP, control: "API9:2023", title: "Improper Inventory Management"},
		{framework: fwNIS2, control: "Art. 21(2)(i)", title: "Human resources security, access control policies and asset management"},
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

// incidentControls are the articles the incident record evidences.
//
// They are kept apart from owaspControls because nothing about a FINDING can
// evidence them. An incident-management obligation is discharged by managing
// incidents; a list of vulnerable endpoints, however long, says nothing about
// whether the entity has a process. So these are driven by the incident record
// itself — and each one states what it takes, because "we have a process" and
// "we have a process that produced a classification and met a deadline" are
// different claims and only the second is evidence.
var incidentControls = []struct {
	ref controlRef
	// need reports whether the incident record supports this control, and the
	// sentence to show as its evidence.
	need func(incidentEvidence) (bool, string)
}{
	{
		controlRef{framework: fwDORA, control: "Art. 17", title: "ICT-related incident management process"},
		func(e incidentEvidence) (bool, string) {
			if e.Total == 0 {
				return false, ""
			}
			return true, fmt.Sprintf("%s tracked through a lifecycle (%d open, %d contained, %d closed)",
				plural(e.Total, "incident"), e.Open, e.Contained, e.Closed)
		},
	},
	{
		controlRef{framework: fwDORA, control: "Art. 18", title: "Classification of ICT-related incidents"},
		func(e incidentEvidence) (bool, string) {
			if e.Classified == 0 {
				return false, ""
			}
			return true, fmt.Sprintf("%d of %s classified against the Art. 18 criteria",
				e.Classified, plural(e.Total, "incident"))
		},
	},
	{
		controlRef{framework: fwDORA, control: "Art. 19", title: "Reporting of major incidents to the competent authority"},
		func(e incidentEvidence) (bool, string) {
			if e.Notified == 0 {
				return false, ""
			}
			return true, fmt.Sprintf("%s with a submission recorded", plural(e.Notified, "incident"))
		},
	},
	{
		controlRef{framework: fwNIS2, control: "Art. 23", title: "Reporting obligations"},
		func(e incidentEvidence) (bool, string) {
			if e.Notified == 0 {
				return false, ""
			}
			return true, fmt.Sprintf("%s with a submission recorded against the 24h / 72h / 1 month timetable",
				plural(e.Notified, "incident"))
		},
	},
}

// unevidencedIncidentControl is what to say when an incident control is not
// supported yet — indexed by control id.
var unevidencedIncidentControl = map[string]string{
	"Art. 17": "no incidents have been recorded, so there is nothing to show a lifecycle for. Set forensic_dsn to enable incident tracking.",
	"Art. 18": "no incident carries a complete Art. 18 classification: clients affected, geographical spread and economic impact are not observable from traffic and must be supplied per incident.",
	"Art. 19": "no submission to a competent authority has been recorded against any incident. AEGIS tracks the deadlines and holds the evidence; filing the report remains a human act.",
	"Art. 23": "no submission has been recorded against the 24h early warning / 72h notification / 1 month final report timetable.",
}

// incidentEvidence is what the compliance mapping needs to know about the
// incident record. A struct rather than the incident package's own type so this
// file stays free of that dependency and testable with a literal.
type incidentEvidence struct {
	Total      int
	Open       int
	Contained  int
	Closed     int
	Classified int
	Notified   int
	Overdue    int
}

// overdueWarning is appended to the report when an obligation has passed unmet.
//
// It is not a finding about the API; it is a finding about the operator, and it
// belongs in a compliance report more than anything else here does. A missed
// 24-hour early warning is a breach of the obligation itself, whatever the
// incident turned out to be.
const overdueWarning = "%s with a reporting deadline that passed and nothing submitted"

// plural writes "1 incident" rather than "1 incidents". A compliance report is
// read by people who will judge the whole document by how carefully it was
// made; the grammar is not a detail there.
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
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
	// GeneratedAt and Tenant are the document's own provenance, carried inside
	// the signed body rather than only in the attestation around it.
	//
	// A signed report used to have exactly one date — attestation.signed_at —
	// and nothing to cross-check it against. Binding that field to the
	// signature (internal/attest) makes it unforgeable, but a document that
	// still cannot say when it is about, or whom it is about, is a weaker
	// artifact than it needs to be: a shared-key deployment could not tell one
	// tenant's signed report from another's.
	GeneratedAt string                `json:"generated_at"`
	Tenant      string                `json:"tenant"`
	Evidence    evidenceProvenance    `json:"evidence"`
	Frameworks  []complianceFramework `json:"frameworks"`
	Summary     struct {
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
func buildCompliance(rows []findingRow, abuse map[string]int, ev incidentEvidence) complianceReport {
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
			// Collected unsorted here and ordered once the set is complete —
			// see the sort below. Truncating during collection would make WHICH
			// issues survive depend on arrival order, the same defect one level
			// down.
			c.Issues = append(c.Issues, issue)
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

	// The incident controls, driven by the incident record rather than by any
	// finding. An unmet deadline is reported as critical: it is a breach of the
	// obligation itself, independent of what the incident turned out to be.
	gaps := map[string][]uncoveredControl{}
	for _, ic := range incidentControls {
		ok, evidence := ic.need(ev)
		if !ok {
			gaps[ic.ref.framework] = append(gaps[ic.ref.framework], uncoveredControl{
				Control: ic.ref.control, Title: ic.ref.title,
				Reason: unevidencedIncidentControl[ic.ref.control],
			})
			continue
		}
		sev := "warning"
		issues := []string{evidence}
		if ev.Overdue > 0 {
			sev = "critical"
			issues = append(issues, fmt.Sprintf(overdueWarning, plural(ev.Overdue, "incident")))
			rep.Summary.Critical += ev.Overdue
		}
		agg[key{ic.ref.framework, ic.ref.control}] = &complianceControl{
			Framework: ic.ref.framework, Control: ic.ref.control, Title: ic.ref.title,
			Severity: sev, Count: ev.Total, Issues: issues,
		}
	}

	// Group controls by framework, ordered OWASP → NIS2 → DORA → ISO, controls by
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
		// A framework with nothing but gaps is still included. Dropping it would
		// make the admission vanish exactly when there is nothing else to
		// balance it — which is when a reader most needs to see it.
		if len(cs) == 0 && len(gaps[fw]) == 0 {
			continue
		}
		sort.SliceStable(cs, func(i, j int) bool {
			if severityRank(cs[i].Severity) != severityRank(cs[j].Severity) {
				return severityRank(cs[i].Severity) < severityRank(cs[j].Severity)
			}
			return cs[i].Control < cs[j].Control
		})
		// Order the issues, then cut. Appending until full and stopping made the
		// surviving issues a function of the order rows arrived in — and this
		// document is signed, so it has to be reproducible from the same state
		// rather than from the same query plan.
		for _, c := range cs {
			sort.Strings(c.Issues)
			if len(c.Issues) > maxIssuesPerControl {
				c.Issues = c.Issues[:maxIssuesPerControl]
			}
		}
		rep.Frameworks = append(rep.Frameworks, complianceFramework{
			Framework: fw, Controls: cs, NotEvidenced: gaps[fw],
		})
	}
	return rep
}
