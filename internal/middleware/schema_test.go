package middleware

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
)

const schemaTestSpec = `
openapi: 3.0.0
info: {title: t, version: "1"}
paths:
  /users:
    post:
      requestBody:
        content:
          application/json:
            schema: {$ref: '#/components/schemas/NewUser'}
      responses: {"201": {description: ok}}
  /search:
    get:
      parameters:
        - {name: q, in: query, required: true, schema: {type: string}}
      responses: {"200": {description: ok}}
components:
  schemas:
    NewUser:
      type: object
      additionalProperties: false
      required: [email]
      properties:
        email: {type: string}
        age: {type: integer}
`

func schemaMW(t *testing.T, cfg config.SchemaConfig) (http.Handler, *bool) {
	t.Helper()
	spec, err := discovery.ParseSpec([]byte(schemaTestSpec))
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		if r.Body != nil {
			_, _ = io.ReadAll(r.Body)
		}
		w.WriteHeader(http.StatusOK)
	})
	h := SchemaValidation(cfg, func(context.Context) *discovery.Spec { return spec }, fakeLogger{}, &fakeStore{})(next)
	return h, &reached
}

func TestSchemaValidation_BlockMode(t *testing.T) {
	h, reached := schemaMW(t, config.SchemaConfig{Enabled: true, BlockMode: true})

	tests := []struct {
		name       string
		method     string
		target     string
		body       string
		wantStatus int
		wantReach  bool
	}{
		{"conforming body", http.MethodPost, "/users", `{"email":"a@b.c","age":3}`, http.StatusOK, true},
		{"mass assignment", http.MethodPost, "/users", `{"email":"a@b.c","is_admin":true}`, http.StatusUnprocessableEntity, false},
		{"missing required param", http.MethodGet, "/search", "", http.StatusUnprocessableEntity, false},
		{"valid param", http.MethodGet, "/search?q=hi", "", http.StatusOK, true},
		{"undocumented passes", http.MethodGet, "/unknown", "", http.StatusOK, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			*reached = false
			var bodyR io.Reader
			if tc.body != "" {
				bodyR = strings.NewReader(tc.body)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, bodyR))
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if *reached != tc.wantReach {
				t.Errorf("backend reached = %v, want %v", *reached, tc.wantReach)
			}
		})
	}
}

func TestSchemaValidation_MonitorMode(t *testing.T) {
	// Monitor never blocks: a violating request still reaches the backend.
	h, reached := schemaMW(t, config.SchemaConfig{Enabled: true, BlockMode: false})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(`{"email":"a@b.c","is_admin":true}`)))
	if rec.Code != http.StatusOK || !*reached {
		t.Errorf("monitor mode should pass through: status=%d reached=%v", rec.Code, *reached)
	}
}

func TestSchemaValidation_BodyRestoredForBackend(t *testing.T) {
	// The body consumed for validation must still be readable by the backend.
	spec, _ := discovery.ParseSpec([]byte(schemaTestSpec))
	var got string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusOK)
	})
	h := SchemaValidation(config.SchemaConfig{Enabled: true, BlockMode: true}, func(context.Context) *discovery.Spec { return spec }, fakeLogger{}, &fakeStore{})(next)

	want := `{"email":"a@b.c","age":3}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(want)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got != want {
		t.Errorf("backend saw body %q, want %q", got, want)
	}
}

func TestSchemaValidation_OversizedBodyBlocked(t *testing.T) {
	// BlockMode must fail closed on an oversized body — an attacker cannot
	// defeat schema enforcement by padding the body past MaxBodyBytes.
	spec, err := discovery.ParseSpec([]byte(schemaTestSpec))
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	h := SchemaValidation(config.SchemaConfig{Enabled: true, BlockMode: true, MaxBodyBytes: 16}, func(context.Context) *discovery.Spec { return spec }, fakeLogger{}, &fakeStore{})(next)

	rec := httptest.NewRecorder()
	body := `{"email":"a@b.c","age":3}` // > 16 bytes
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(body)))

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
	if reached {
		t.Error("backend should not be reached when body exceeds the schema validation cap in block mode")
	}
}

func TestSchemaValidation_OversizedBodyMonitorPassesThroughWithSignal(t *testing.T) {
	// Monitor mode still passes an oversized body through (fail-open by design),
	// but must record the skip so it's visible to operators, not silent.
	spec, err := discovery.ParseSpec([]byte(schemaTestSpec))
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	reached := false
	var gotBody string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	})
	store := &fakeStore{}
	h := SchemaValidation(config.SchemaConfig{Enabled: true, BlockMode: false, MaxBodyBytes: 16}, func(context.Context) *discovery.Spec { return spec }, fakeLogger{}, store)(next)

	rec := httptest.NewRecorder()
	body := `{"email":"a@b.c","age":3}` // > 16 bytes
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(body)))

	if rec.Code != http.StatusOK || !reached {
		t.Errorf("monitor mode should pass oversized body through: status=%d reached=%v", rec.Code, reached)
	}
	if gotBody != body {
		t.Errorf("backend saw body %q, want %q (must be reassembled from the bounded read)", gotBody, body)
	}
	if store.metrics["schema_skipped_oversized"] == 0 {
		t.Error("expected schema_skipped_oversized metric to be recorded even in monitor mode")
	}
}

func TestSchemaValidation_Disabled(t *testing.T) {
	// Disabled (or nil spec) must be a pure passthrough.
	if got := SchemaValidation(config.SchemaConfig{Enabled: false}, nil, fakeLogger{}, &fakeStore{}); got == nil {
		t.Fatal("expected a middleware")
	}
	h, reached := schemaMW(t, config.SchemaConfig{Enabled: false})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(`{"bogus":1}`)))
	if !*reached || rec.Code != http.StatusOK {
		t.Errorf("disabled should pass through: status=%d reached=%v", rec.Code, *reached)
	}
}
