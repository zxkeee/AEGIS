package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"api-gateway/internal/config"
)

func consumerIDCfg() config.ConsumerIDConfig {
	return config.ConsumerIDConfig{
		Enabled: true,
		Headers: []string{"X-API-Key"},
		Cookies: []string{"session"},
	}
}

// run sends r through ConsumerID and returns the pseudonym it assigned, if any.
func runConsumerID(t *testing.T, cfg config.ConsumerIDConfig, secret string, r *http.Request) string {
	t.Helper()
	var got string
	h := ConsumerID(cfg, secret)(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		got = req.Header.Get("X-Gateway-Consumer-Key")
	}))
	h.ServeHTTP(httptest.NewRecorder(), r)
	return got
}

func req(headers map[string]string, cookies map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/orders/42", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	for k, v := range cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	return r
}

// The property everything else depends on: the same credential always yields the
// same id, and different credentials never share one. Object-ownership
// detection only ever compares identities for equality.
func TestConsumerID_StableAndDistinct(t *testing.T) {
	cfg, secret := consumerIDCfg(), "salt"

	a1 := runConsumerID(t, cfg, secret, req(map[string]string{"Authorization": "Bearer opaque-token-alice"}, nil))
	a2 := runConsumerID(t, cfg, secret, req(map[string]string{"Authorization": "Bearer opaque-token-alice"}, nil))
	b := runConsumerID(t, cfg, secret, req(map[string]string{"Authorization": "Bearer opaque-token-bob"}, nil))

	if a1 == "" {
		t.Fatal("no identity assigned to a bearer-token caller")
	}
	if a1 != a2 {
		t.Errorf("same credential gave two identities: %q and %q", a1, a2)
	}
	if a1 == b {
		t.Errorf("different credentials collided on %q", a1)
	}
}

// The credential must not be recoverable from what gets stored. A plain digest
// would not do — API keys and session ids come from small enough spaces to
// search — so the salt has to change the output.
func TestConsumerID_CredentialIsNotRecoverable(t *testing.T) {
	cfg := consumerIDCfg()
	const cred = "opaque-token-alice"

	id := runConsumerID(t, cfg, "salt-one", req(map[string]string{"Authorization": "Bearer " + cred}, nil))
	other := runConsumerID(t, cfg, "salt-two", req(map[string]string{"Authorization": "Bearer " + cred}, nil))

	if id == other {
		t.Error("the salt does not affect the identity — an unkeyed digest is searchable back to a live credential")
	}
	if got := id[len("token:"):]; len(got) == 0 {
		t.Fatal("empty identity")
	}
	// The credential itself must appear nowhere in the id.
	if containsSub(id, cred) {
		t.Errorf("identity %q contains the credential", id)
	}
}

func containsSub(hay, needle string) bool {
	return len(needle) > 0 && len(hay) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(hay); i++ {
				if hay[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}()
}

// A verified JWT subject is a real identity; deriving a pseudonym from the same
// request as well would split one caller across two consumer records.
func TestConsumerID_VerifiedSubjectWins(t *testing.T) {
	r := req(map[string]string{
		"Authorization":     "Bearer opaque-token",
		"X-Gateway-Subject": "alice@example.com",
	}, nil)
	if got := runConsumerID(t, consumerIDCfg(), "salt", r); got != "" {
		t.Errorf("assigned %q despite a verified subject", got)
	}
}

// A JWT that reached here is one auth did not verify (or did not enforce).
// Minting an identity from its unverified contents would let a caller
// manufacture as many identities as it likes by varying the signature.
func TestConsumerID_IgnoresUnverifiedJWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"
	if got := runConsumerID(t, consumerIDCfg(), "salt",
		req(map[string]string{"Authorization": "Bearer " + jwt}, nil)); got != "" {
		t.Errorf("minted %q from an unverified JWT", got)
	}
}

func TestConsumerID_CredentialSources(t *testing.T) {
	cfg, secret := consumerIDCfg(), "salt"

	tests := []struct {
		name    string
		headers map[string]string
		cookies map[string]string
		want    bool
	}{
		{"bearer", map[string]string{"Authorization": "Bearer abc123"}, nil, true},
		{"basic", map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}, nil, true},
		{"token scheme", map[string]string{"Authorization": "Token abc123"}, nil, true},
		{"configured header", map[string]string{"X-API-Key": "abc123"}, nil, true},
		{"configured cookie", nil, map[string]string{"session": "abc123"}, true},
		{"unconfigured header is ignored", map[string]string{"X-Other": "abc123"}, nil, false},
		{"unconfigured cookie is ignored", nil, map[string]string{"other": "abc123"}, false},
		{"no credential", nil, nil, false},
		{"empty bearer", map[string]string{"Authorization": "Bearer "}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runConsumerID(t, cfg, secret, req(tt.headers, tt.cookies))
			if (got != "") != tt.want {
				t.Errorf("identity = %q, want assigned = %v", got, tt.want)
			}
		})
	}
}

// An Authorization header is a deliberate statement of identity; a cookie is
// attached by the browser whether or not the caller meant to authenticate.
func TestConsumerID_HeaderBeatsCookie(t *testing.T) {
	cfg, secret := consumerIDCfg(), "salt"
	viaHeader := runConsumerID(t, cfg, secret, req(map[string]string{"Authorization": "Bearer tok"}, nil))
	both := runConsumerID(t, cfg, secret,
		req(map[string]string{"Authorization": "Bearer tok"}, map[string]string{"session": "other"}))
	if viaHeader != both {
		t.Errorf("a cookie changed the identity: %q vs %q", viaHeader, both)
	}
}

func TestConsumerID_DisabledIsPassthrough(t *testing.T) {
	cfg := consumerIDCfg()
	cfg.Enabled = false
	if got := runConsumerID(t, cfg, "salt",
		req(map[string]string{"Authorization": "Bearer tok"}, nil)); got != "" {
		t.Errorf("assigned %q while disabled", got)
	}
}

func TestLooksLikeJWT(t *testing.T) {
	tests := map[string]bool{
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.sig": true,
		"a.b.c":          true,
		"opaque-token":   false,
		"two.parts":      false,
		"four.parts.a.b": false,
		"":               false,
		".leading":       false,
	}
	for in, want := range tests {
		if got := looksLikeJWT(in); got != want {
			t.Errorf("looksLikeJWT(%q) = %v, want %v", in, got, want)
		}
	}
}
