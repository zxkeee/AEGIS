package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"api-gateway/internal/middleware"
)

// postLogin issues a POST /api/login with the given JSON body and returns the
// recorder.
func postLogin(h *handlers, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(b))
	r.RemoteAddr = "198.51.100.5:2222"
	rec := httptest.NewRecorder()
	h.login(rec, r)
	return rec
}

func cookieByName(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestLogin_AuthDisabled(t *testing.T) {
	h, _ := redisHandlers(t) // redisHandlers sets AdminAuth=false
	rec := postLogin(h, map[string]string{"secret": "anything"})
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusOK || body["auth"] != false {
		t.Fatalf("auth-disabled login = %d %v", rec.Code, body)
	}
}

func TestLogin_ValidSecret_SetsSessionAndCSRF(t *testing.T) {
	h, _ := redisHandlers(t)
	h.cfg.AdminAuth = true

	rec := postLogin(h, map[string]string{"secret": h.cfg.AdminSecret})
	if rec.Code != http.StatusOK {
		t.Fatalf("valid secret = %d", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["auth"] != true || body["tenant"] != "default" {
		t.Fatalf("login body = %v", body)
	}

	// Session cookie must be HttpOnly; CSRF cookie must be readable by JS.
	sc := cookieByName(rec, middleware.SessionCookie)
	if sc == nil || !sc.HttpOnly || sc.Value == "" {
		t.Fatalf("session cookie = %+v", sc)
	}
	cc := cookieByName(rec, middleware.CSRFCookie)
	if cc == nil || cc.HttpOnly {
		t.Fatalf("csrf cookie = %+v", cc)
	}
	// Body CSRF must equal the cookie CSRF (double-submit) and be bound to the
	// stored session.
	if body["csrf"] != cc.Value {
		t.Fatalf("csrf mismatch: body=%v cookie=%v", body["csrf"], cc.Value)
	}
	sess, ok, err := h.store.ValidateSession(context.Background(), sc.Value)
	if err != nil || !ok {
		t.Fatalf("session not stored: ok=%v err=%v", ok, err)
	}
	if !sess.SuperAdmin || sess.CSRF != cc.Value {
		t.Fatalf("stored session = %+v", sess)
	}
}

func TestLogin_WrongSecret_NoSession(t *testing.T) {
	h, _ := redisHandlers(t)
	h.cfg.AdminAuth = true
	rec := postLogin(h, map[string]string{"secret": "definitely-wrong"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret = %d, want 401", rec.Code)
	}
	if cookieByName(rec, middleware.SessionCookie) != nil {
		t.Fatal("session cookie set on failed login")
	}
}

// A successful login must not consume brute-force budget (the gate only charges
// on failure).
func TestLogin_SuccessDoesNotConsumeBudget(t *testing.T) {
	h, _ := redisHandlers(t)
	h.cfg.AdminAuth = true
	_ = postLogin(h, map[string]string{"secret": h.cfg.AdminSecret})
	n, err := h.store.GetRate(context.Background(), "loginfail:198.51.100.5")
	if err != nil {
		t.Fatalf("GetRate: %v", err)
	}
	if n != 0 {
		t.Fatalf("success consumed budget: counter = %d", n)
	}
}

func TestLogin_PasswordPath_NoUserStore(t *testing.T) {
	h, _ := redisHandlers(t) // users == nil (no forensic_dsn)
	h.cfg.AdminAuth = true
	rec := postLogin(h, map[string]string{"email": "a@b.io", "password": "longlonglong12"})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("password login without store = %d, want 503", rec.Code)
	}
}

func TestLogin_EmptyBody(t *testing.T) {
	h, _ := redisHandlers(t)
	h.cfg.AdminAuth = true
	rec := postLogin(h, map[string]string{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty credentials = %d, want 400", rec.Code)
	}
}

func TestLogout_InvalidatesSession(t *testing.T) {
	h, _ := redisHandlers(t)
	h.cfg.AdminAuth = true

	// Establish a session via secret login.
	rec := postLogin(h, map[string]string{"secret": h.cfg.AdminSecret})
	sc := cookieByName(rec, middleware.SessionCookie)
	if sc == nil {
		t.Fatal("no session to log out")
	}

	// Logout carrying that cookie.
	r := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	r.AddCookie(&http.Cookie{Name: middleware.SessionCookie, Value: sc.Value})
	rec2 := httptest.NewRecorder()
	h.logout(rec2, r)
	if rec2.Code != http.StatusOK {
		t.Fatalf("logout = %d", rec2.Code)
	}
	// Session must be gone from the store.
	if _, ok, _ := h.store.ValidateSession(context.Background(), sc.Value); ok {
		t.Fatal("session still valid after logout")
	}
	// And the cookie must be cleared (MaxAge < 0).
	cleared := cookieByName(rec2, middleware.SessionCookie)
	if cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("session cookie not cleared: %+v", cleared)
	}
}
