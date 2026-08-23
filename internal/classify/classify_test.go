package classify

import (
	"reflect"
	"testing"
)

func TestDetect_Types(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"valid visa", "card 4111 1111 1111 1111 on file", []string{"credit_card"}},
		{"email", "reach me at jane.doe@example.com", []string{"email"}},
		{"ssn", "ssn 123-45-6789", []string{"ssn"}},
		{"phone", "call (415) 555-0132 today", []string{"phone"}},
		{"mixed", "a@b.io paid with 4111111111111111", []string{"credit_card", "email"}},
		// A bare 10-digit run also matches the phone pattern by shape — both
		// fire, which is correct: an NPI genuinely looks like a phone number.
		{"npi", "referring provider NPI: 1234567893", []string{"npi", "phone"}},
		{"npi hash-separated", "NPI#1234567893", []string{"npi", "phone"}},
		{"none", `{"order_id": 8675309, "qty": 3}`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Detect([]byte(c.in))
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("Detect(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// Luhn precision: a 16-digit number that is NOT Luhn-valid (e.g. an order ID)
// must NOT be reported as a credit card.
func TestDetect_LuhnRejectsNonCard(t *testing.T) {
	if got := Detect([]byte("ref 1234567890123456")); got != nil {
		t.Fatalf("non-Luhn 16-digit should not be a card, got %v", got)
	}
	// Valid Luhn number IS a card.
	if got := Detect([]byte("4111111111111111")); !reflect.DeepEqual(got, []string{"credit_card"}) {
		t.Fatalf("valid Luhn = %v, want [credit_card]", got)
	}
}

// SSN validator rejects structurally-invalid ranges.
func TestDetect_SSNValidation(t *testing.T) {
	if got := Detect([]byte("000-12-3456")); got != nil {
		t.Fatalf("area 000 must be rejected, got %v", got)
	}
	if got := Detect([]byte("666-12-3456")); got != nil {
		t.Fatalf("area 666 must be rejected, got %v", got)
	}
}

// NPI is the one PHI-category detector; verify Categories actually surfaces
// PHI (it's a documented category in the package doc comment, but was
// previously unreachable — no detector ever produced it).
func TestDetect_NPIValidatesCheckDigit(t *testing.T) {
	// 1234567893 is the standard CMS-documented example of a valid NPI. It
	// also matches the phone-shape detector — both are correct, an NPI
	// genuinely looks like a phone number by digit shape alone.
	if got := Detect([]byte("NPI: 1234567893")); !reflect.DeepEqual(got, []string{"npi", "phone"}) {
		t.Fatalf("valid NPI = %v, want [npi phone]", got)
	}
	// Bad check digit (last digit flipped) must not be reported as npi
	// (though it may still match the phone-shape detector).
	if got := Detect([]byte("NPI: 1234567890")); contains(got, "npi") {
		t.Fatalf("invalid check digit should not be reported as npi, got %v", got)
	}
	// A bare 10-digit run with no "NPI" label must not be flagged as npi —
	// this is what keeps it from colliding with ordinary phone numbers/IDs
	// (it may still legitimately match the phone-shape detector).
	if got := Detect([]byte("call center ext 1234567893")); contains(got, "npi") {
		t.Fatalf("unlabelled 10-digit number must not be reported as npi, got %v", got)
	}
}

func TestCategories_IncludesPHI(t *testing.T) {
	got := Categories([]string{"npi"})
	if !reflect.DeepEqual(got, []string{"PHI"}) {
		t.Fatalf("Categories([npi]) = %v, want [PHI]", got)
	}
}

func TestRedact_MasksAndReportsTypes(t *testing.T) {
	in := []byte("email a@b.io card 4111 1111 1111 1111")
	out, types := Redact(in, []byte("***"))
	if reflect.DeepEqual(out, in) {
		t.Fatal("Redact did not modify the body")
	}
	if !reflect.DeepEqual(types, []string{"credit_card", "email"}) {
		t.Fatalf("types = %v", types)
	}
	if string(out) == "" || containsDigits(out) && containsCard(out) {
		t.Fatalf("card not masked: %q", out)
	}
}

func TestCategories(t *testing.T) {
	got := Categories([]string{"credit_card", "email", "ssn"})
	want := []string{"PCI", "PII"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Categories = %v, want %v", got, want)
	}
	if Categories(nil) != nil {
		t.Fatal("Categories(nil) should be nil")
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func containsDigits(b []byte) bool {
	for _, c := range b {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}

// containsCard reports whether a full 16-digit run survives (i.e. not masked).
func containsCard(b []byte) bool {
	return len(Detect(b)) > 0
}
