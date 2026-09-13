package discovery

import (
	"strconv"
	"strings"

	"api-gateway/internal/classify"
)

// dataLabel renders the classified data types of an endpoint into a compact,
// compliance-aware label, e.g. "PCI (credit_card), PII (email)". Falls back to a
// generic "sensitive data" when the types are unknown (custom DLP patterns).
func dataLabel(types []string) string {
	if len(types) == 0 {
		return "sensitive data"
	}
	cats := classify.Categories(types)
	if len(cats) == 0 {
		return "sensitive data (" + strings.Join(types, ", ") + ")"
	}
	return strings.Join(cats, "/") + " (" + strings.Join(types, ", ") + ")"
}

// Finding is a discrete, named security issue derived from an endpoint's
// observed traffic and effective controls. Unlike the numeric RiskScore, a
// Finding names the specific OWASP API risk and explains why it fired, so an
// operator (or an alert) can act on it directly.
type Finding struct {
	Code     string `json:"code"`     // stable slug, e.g. "sensitive_data_no_auth"
	OWASP    string `json:"owasp"`    // mapped OWASP API Top-10 id
	Severity string `json:"severity"` // critical | warning | info
	Title    string `json:"title"`
	Why      string `json:"why"`
	// Evidence states what backs this finding. See EvidenceRef.
	Evidence EvidenceRef `json:"evidence"`
}

// Evidence kinds. A reader must be able to tell a finding whose individual
// occurrences were recorded from one that exists only as a tally.
const (
	// EvidenceEvents: individual occurrences are in the forensic record and can
	// be retrieved for any period, by the reasons listed on the finding.
	EvidenceEvents = "events"
	// EvidenceCounters: the finding was derived from aggregate counters. The
	// occurrences behind them were never written down, so there is nothing to
	// retrieve — which is NOT the same as there being no occurrences.
	EvidenceCounters = "counters"
)

// EvidenceRef says where the proof of a finding lives.
//
// It exists because "we saw no evidence" and "we kept no evidence" are opposite
// statements that an empty result cannot distinguish. An auditor asking "show me
// the requests behind this" must be told plainly when the answer is that they
// were counted and not retained, rather than handed an empty list that reads as
// an all-clear.
type EvidenceRef struct {
	// Kind is EvidenceEvents or EvidenceCounters.
	Kind string `json:"kind"`
	// Reasons are the forensic reason codes carrying this finding's occurrences.
	// Only set when Kind is EvidenceEvents.
	Reasons []string `json:"reasons,omitempty"`
	// Note explains the absence when Kind is EvidenceCounters.
	Note string `json:"note,omitempty"`
}

// countersOnly is the evidence descriptor shared by the data-exposure findings.
// They are computed from per-endpoint tallies the catalog rolls up; the
// individual responses that incremented those tallies are not retained, so no
// query can produce them. Recording a bounded sample of them is the open work
// this descriptor exists to make visible rather than to paper over.
func countersOnly() EvidenceRef {
	return EvidenceRef{
		Kind: EvidenceCounters,
		Note: "derived from per-endpoint counters; the individual responses behind them are not retained, " +
			"so this cannot be evidenced request by request",
	}
}

// DetectFindings derives findings for an endpoint from its accumulated counters
// and the effective controls. It is a pure function of its inputs so it is fully
// unit-testable without a database. `matched` is false for shadow endpoints
// (observed traffic with no configured route).
//
// v1 focuses on the highest-value, data-centric signal — sensitive data exposed
// without authentication (OWASP API3 Excessive Data Exposure + API2 Broken
// Authentication) — built entirely on counters the catalog already maintains.
// exposureSeverity grades a data exposure by WHAT was exposed, not merely that
// something was.
//
// Every sensitive_data finding used to be critical. Measured against a real
// third-party API (demo/fp-assessment, Codeberg), that produced ten critical
// findings, all of them "this endpoint returns committer email addresses to
// anonymous callers" — on a public code host, where those addresses are in the
// commit objects by design and the API exists to serve them.
//
// The detection was right and the grade was wrong, and a grade that is wrong in
// the alarming direction is not the safe option: an operator who finds ten
// criticals that are all the same benign fact learns to skim the list, and the
// eleventh — an actual card number — is skimmed with it.
//
// So severity follows the data class:
//
//   - PCI (card numbers) or PHI (health identifiers) reaching an unauthenticated
//     caller is critical. There is no ordinary reason for either, and both carry
//     their own regulatory regime.
//   - Ordinary PII — an email address, a phone number — is a warning. It is
//     frequently deliberate (a public profile, a commit author, a support
//     contact) and the operator is the only one who can say which it is.
//
// A mixture grades by its worst class: an endpoint returning both a card and an
// email is critical, because the card is.
func exposureSeverity(piiTypes []string) string {
	for _, cat := range classify.Categories(piiTypes) {
		if cat == classify.CategoryPCI || cat == classify.CategoryPHI {
			return "critical"
		}
	}
	return "warning"
}

func DetectFindings(e Endpoint, c Controls, matched bool) []Finding {
	var out []Finding

	if e.PIICount > 0 {
		label := dataLabel(e.PIITypes)
		switch {
		case e.AnonCount > 0:
			// Confirmed: sensitive data was returned AND at least some callers
			// carried no identity. This is an active exposure, not a hypothetical.
			out = append(out, Finding{
				Code:     "sensitive_data_no_auth",
				OWASP:    "API3:2023",
				Severity: exposureSeverity(e.PIITypes),
				Title:    "Sensitive data exposed to unauthenticated callers",
				Why: "endpoint returned " + label + " on " + strconv.FormatInt(e.PIICount, 10) +
					" response(s) while " + strconv.FormatInt(e.AnonCount, 10) +
					" request(s) arrived without authentication",
				Evidence: countersOnly(),
			})
		case !c.AuthRequired:
			// Latent: data is returned and the endpoint does not enforce auth, so
			// the exposure is one unauthenticated request away even though every
			// observed caller happened to present a token.
			out = append(out, Finding{
				Code:     "sensitive_data_auth_not_required",
				OWASP:    "API3:2023",
				Severity: "warning",
				Title:    "Sensitive data on an endpoint that does not require authentication",
				Why: "endpoint returned " + label + " on " + strconv.FormatInt(e.PIICount, 10) +
					" response(s) and authentication is not enforced by its configuration",
				Evidence: countersOnly(),
			})
		}
	}

	// Shadow endpoint actively serving sensitive data is doubly dangerous: it is
	// undocumented AND leaking PII.
	if !matched && e.PIICount > 0 {
		out = append(out, Finding{
			Code:     "shadow_sensitive_data",
			OWASP:    "API9:2023",
			Severity: "critical",
			Title:    "Undocumented (shadow) endpoint serving sensitive data",
			Why: "endpoint matches no configured route yet returned " + dataLabel(e.PIITypes) +
				" on " + strconv.FormatInt(e.PIICount, 10) + " response(s)",
			Evidence: countersOnly(),
		})
	}

	return out
}
