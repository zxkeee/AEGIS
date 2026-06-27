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
}

// DetectFindings derives findings for an endpoint from its accumulated counters
// and the effective controls. It is a pure function of its inputs so it is fully
// unit-testable without a database. `matched` is false for shadow endpoints
// (observed traffic with no configured route).
//
// v1 focuses on the highest-value, data-centric signal — sensitive data exposed
// without authentication (OWASP API3 Excessive Data Exposure + API2 Broken
// Authentication) — built entirely on counters the catalog already maintains.
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
				Severity: "critical",
				Title:    "Sensitive data exposed to unauthenticated callers",
				Why: "endpoint returned " + label + " on " + strconv.FormatInt(e.PIICount, 10) +
					" response(s) while " + strconv.FormatInt(e.AnonCount, 10) +
					" request(s) arrived without authentication",
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
		})
	}

	return out
}
