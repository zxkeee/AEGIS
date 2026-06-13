package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCleanHeaders_StripsSpoofedIdentity(t *testing.T) {
	var seen http.Header
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
	})
	h := CleanHeaders()(next)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Gateway-Subject", "admin")         // spoofed identity
	r.Header.Set("X-Gateway-Roles", "superuser")       // spoofed roles
	r.Header.Set("x-gateway-signature", "deadbeef")    // case-insensitive
	r.Header.Set("Authorization", "Bearer real-token") // must be preserved

	h.ServeHTTP(httptest.NewRecorder(), r)

	for k := range seen {
		if len(k) >= 10 && (k[:10] == "X-Gateway-" || k[:10] == "x-gateway-") {
			t.Fatalf("spoofed header %q reached the backend", k)
		}
	}
	if seen.Get("X-Gateway-Subject") != "" || seen.Get("X-Gateway-Roles") != "" || seen.Get("X-Gateway-Signature") != "" {
		t.Fatal("X-Gateway-* headers were not stripped")
	}
	if seen.Get("Authorization") != "Bearer real-token" {
		t.Fatal("Authorization header must be preserved")
	}
}
