package middleware

import (
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
