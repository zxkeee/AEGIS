// Package classify is the data-classification engine: it identifies the TYPES of
// sensitive data in a payload (credit card, SSN, email, phone) and maps them to
// compliance categories (PCI / PII / PHI). It is a leaf package (stdlib only) so
// both the DLP middleware and the discovery catalog can use it without a cycle.
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
	{"phone", CategoryPII, regexp.MustCompile(`\b(?:\+?\d{1,2}[ .\-]?)?\(?\d{3}\)?[ .\-]?\d{3}[ .\-]?\d{4}\b`), validPhone},
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
// Luhn-valid number — the standard payment-card checksum.
func luhnValid(s string) bool {
	digits := make([]int, 0, len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
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

// validPhone rejects matches that are really longer digit runs (e.g. a card or
// an ID) by requiring the match not to be immediately part of a longer number.
// The regex already anchors on word boundaries; this rejects all-same-digit
// runs which are almost always test/placeholder noise.
func validPhone(s string) bool {
	var digits []rune
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, r)
		}
	}
	if len(digits) < 10 {
		return false
	}
	allSame := true
	for _, d := range digits[1:] {
		if d != digits[0] {
			allSame = false
			break
		}
	}
	return !allSame
}
