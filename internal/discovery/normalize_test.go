package discovery

import "testing"

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"/":                           "/",
		"":                            "/",
		"/api/v1/users":               "/api/v1/users",
		"/api/v1/users/42":            "/api/v1/users/{id}",
		"/api/v1/users/42/":           "/api/v1/users/{id}",
		"/api/v1/users/42/orders/100": "/api/v1/users/{id}/orders/{id}",
		"/files/550e8400-e29b-41d4-a716-446655440000": "/files/{id}",
		"/blob/deadbeefdeadbeefcafe":                  "/blob/{id}",
		"/t/abc123def456ghi789xyz0":                   "/t/{id}",
		"/health":                                     "/health",
		"/api/orders/status":                          "/api/orders/status",
	}
	for in, want := range cases {
		if got := NormalizePath(in); got != want {
			t.Errorf("NormalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeDoesNotCollapseWords(t *testing.T) {
	// Pure alphabetic segments must stay intact even if long.
	if got := NormalizePath("/api/administration/configuration"); got != "/api/administration/configuration" {
		t.Errorf("unexpected collapse: %q", got)
	}
}

func TestEndpointKey(t *testing.T) {
	if got := EndpointKey("get", "/api/users/7"); got != "GET /api/users/{id}" {
		t.Errorf("EndpointKey = %q", got)
	}
}
