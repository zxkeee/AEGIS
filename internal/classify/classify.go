// Package classify is the data-classification engine: it identifies the TYPES of
// sensitive data in a payload (credit card, SSN, email, phone, NPI) and maps
// them to compliance categories (PCI / PII / PHI). It is a leaf package
// (stdlib only) so both the DLP middleware and the discovery catalog can use
// it without a cycle.
//
// Typing matters because "this endpoint leaks payment-card data (PCI) to
// unauthenticated callers" is a far more actionable — and sellable — finding
// than a generic "PII detected". Validators (e.g. the Luhn check on card
// numbers) keep precision high so a 16-digit order ID is not reported as a card.
package classify

import (
	"regexp"
	"sort"
	"strings"
)

// Compliance categories a data type can belong to.
const (
	CategoryPCI = "PCI" // payment card data
	CategoryPII = "PII" // personally identifiable information
	CategoryPHI = "PHI" // protected health information
)

// npiConstant is the CMS-assigned constant prefixed to a 10-digit NPI before
// Luhn-validating its check digit (see validNPI).
const npiConstant = "80840"

type detector struct {
	Type     string
	Category string
	re       *regexp.Regexp
	// validate is an optional second-stage check that rejects regex matches which
	// are not genuine instances of the type (false-positive control).
	validate func(string) bool
}

// detectors are evaluated in order. Card is first (and Luhn-validated) so a
// number that is also card-shaped is consumed as PCI before looser patterns see
// it. Each match is masked before later detectors run, preventing double counts.
var detectors = []detector{
	{"credit_card", CategoryPCI, regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`), luhnValid},
	{"ssn", CategoryPII, regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), validSSN},
	{"email", CategoryPII, regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`), nil},
	// The leading "+" sits OUTSIDE the word boundary: `\b` cannot hold between a
	// space and a "+", so anchoring the whole pattern with `\b` dropped the plus
	// from every compact E.164 number ("+14155550132") and left validPhone
	// looking at bare digits.
	//
	// Known gap: the grouping is US-shaped (3-3-4), so "+44 20 7946 0958" does
	// not match at all. That predates the precision work and is a recall
	// question, not a false-positive one.
	{"phone", CategoryPII, regexp.MustCompile(`(?:\+[ .\-]?)?\b(?:\d{1,2}[ .\-]?)?\(?\d{3}\)?[ .\-]?\d{3}[ .\-]?\d{4}\b`), validPhone},
	// npi: a bare 10-digit run is indistinguishable from a phone number or any
	// other numeric ID, so this only fires next to an explicit "NPI" label —
	// the same precision-over-recall tradeoff as the other detectors, applied
	// via context instead of a value-shape check. The check-digit validation
	// (validNPI) is the CMS Luhn-variant algorithm, not a shape heuristic.
	{"npi", CategoryPHI, regexp.MustCompile(`(?i)\bNPI\b[:#\s]{0,3}(\d{10})\b`), validNPI},
}

// typeCategory maps a data type to its compliance category.
var typeCategory = func() map[string]string {
	m := make(map[string]string, len(detectors))
	for _, d := range detectors {
		m[d.Type] = d.Category
	}
	return m
}()

// Detect returns the distinct sensitive data types present in b (e.g.
// ["credit_card","email"]), sorted. It does not modify b.
func Detect(b []byte) []string {
	found := map[string]bool{}
	for _, d := range detectors {
		for _, m := range d.re.FindAll(b, -1) {
			if d.validate != nil && !d.validate(string(m)) {
				continue
			}
			found[d.Type] = true
			break // one confirmed match of a type is enough to flag it
		}
	}
	return sortedKeys(found)
}

// Redact replaces every validated match with mask and returns the new bytes plus
// the distinct types that were redacted (sorted). Used by the DLP middleware so
// redaction and classification share one source of truth.
func Redact(b, mask []byte) ([]byte, []string) {
	found := map[string]bool{}
	for i := range detectors {
		d := detectors[i]
		b = d.re.ReplaceAllFunc(b, func(m []byte) []byte {
			if d.validate != nil && !d.validate(string(m)) {
				return m // leave non-genuine matches untouched
			}
			found[d.Type] = true
			return mask
		})
	}
	return b, sortedKeys(found)
}

// Categories maps a set of data types to the distinct compliance categories they
// belong to (e.g. ["credit_card","email"] -> ["PCI","PII"]), sorted.
func Categories(types []string) []string {
	set := map[string]bool{}
	for _, t := range types {
		if c, ok := typeCategory[t]; ok {
			set[c] = true
		}
	}
	return sortedKeys(set)
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// luhnValid strips separators and reports whether the digits form a 13–19 digit
// Luhn-valid number that also begins with a digit payment cards actually use.
//
// The checksum alone is far too weak to stand on. Luhn catches single-digit
// typos, not category errors: roughly one in ten arbitrary numbers of the right
// length passes it. Against a live Forgejo it accepted the ORCID
// "0000-0003-1124-3174" out of a repository description and reported it as
// exposed cardholder data (assessment, 2026-08-31) — the single worst thing
// this detector can get wrong, because PCI is the category that makes a reader
// stop reading.
//
// The first digit is the ISO/IEC 7812 Major Industry Identifier, and every
// payment network in use sits in 2–6: Mastercard 2 and 51–55, Amex 34/37,
// Diners 36/38–39, JCB 35, Visa 4, Discover 6, UnionPay 62. Nothing issued for
// payment begins with 0, 1, 7, 8 or 9. That one check removes every ORCID (all
// currently allocated ones begin 0000-), ISBN-13 (978/979) and the long numeric
// ids that make up the bulk of real API payloads, and costs no recall on any
// card a customer could actually be leaking.
func luhnValid(s string) bool {
	digits := onlyDigits(s)
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	if digits[0] < '2' || digits[0] > '6' {
		return false
	}
	return luhnChecksumValid(digits)
}

// validNPI reports whether s contains exactly one 10-digit National Provider
// Identifier with a valid check digit. Per the CMS algorithm, the check digit
// is valid when the 10-digit NPI, prefixed with the constant "80840", passes
// the standard Luhn checksum. s is the full regex match (label text plus the
// number); the label contributes no digits, so extracting all digits from it
// yields exactly the 10-digit NPI.
func validNPI(s string) bool {
	digits := onlyDigits(s)
	if len(digits) != 10 {
		return false
	}
	return luhnChecksumValid(npiConstant + digits)
}

// onlyDigits returns the numeric digits of s as a string, discarding
// everything else (separators, labels, etc.).
func onlyDigits(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= '0' && c <= '9' {
			b = append(b, c)
		}
	}
	return string(b)
}

// luhnChecksumValid applies the standard Luhn algorithm to a digit string.
func luhnChecksumValid(digits string) bool {
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// validSSN rejects the structurally-invalid US SSN ranges so random 3-2-4 digit
// strings are not reported as SSNs.
func validSSN(s string) bool {
	p := strings.Split(s, "-")
	if len(p) != 3 {
		return false
	}
	area, grp, ser := p[0], p[1], p[2]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if grp == "00" || ser == "0000" {
		return false
	}
	return true
}

// validPhone requires a match to LOOK like a written phone number, not merely
// to contain ten digits.
//
// This is the same conclusion the npi detector above already reached — a bare
// ten-digit run is indistinguishable from any other numeric identifier — but it
// had not been applied here, and the consequence showed up the moment the
// gateway saw a real API: "1510782819", the unix timestamp in a git commit's
// author line, was reported as an exposed phone number on every repository
// browsed (assessment, 2026-08-31). Object ids, timestamps, sequence numbers
// and counters all have that shape, and they are what API payloads are mostly
// made of.
//
// A number a human wrote down as a phone number carries punctuation — a leading
// "+", parentheses around the area code, or spaces/dots/hyphens between the
// groups. A number a machine emitted as an identifier does not. Requiring at
// least one of those gives up bare "5551234567" and keeps every conventionally
// formatted number, which is the right side of that trade for a control whose
// output goes in front of a customer.
func validPhone(s string) bool {
	var digits []rune
	formatted := false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits = append(digits, r)
		case r == '+' || r == '(' || r == ')' || r == ' ' || r == '.' || r == '-':
			formatted = true
		}
	}
	if len(digits) < 10 || !formatted {
		return false
	}
	// All-same-digit runs are placeholder noise ("0000000000", "9999999999").
	for _, d := range digits[1:] {
		if d != digits[0] {
			return true
		}
	}
	return false
}
