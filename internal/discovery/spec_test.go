package discovery

import "testing"

const openapi3YAML = `
openapi: 3.0.1
info:
  title: Demo
  version: "1.0"
paths:
  /users:
    get: {summary: list}
    post: {summary: create}
  /users/{userId}:
    get: {summary: read}
    delete: {summary: remove}
  /health:
    get: {}
`

func TestParseSpec_OpenAPI3(t *testing.T) {
	s, err := ParseSpec([]byte(openapi3YAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Version != "openapi:3" {
		t.Fatalf("version = %q", s.Version)
	}
	// {userId} must collapse to {id} so it matches normalized live traffic.
	if !s.HasOp("GET", "/users/{id}") {
		t.Error("GET /users/{id} should be documented")
	}
	if !s.HasOp("DELETE", "/users/{id}") {
		t.Error("DELETE /users/{id} should be documented")
	}
	if !s.HasOp("POST", "/users") {
		t.Error("POST /users should be documented")
	}
	// Case-insensitive method lookup.
	if !s.HasOp("get", "/health") {
		t.Error("lowercase method lookup should work")
	}
	if s.HasOp("PUT", "/users") {
		t.Error("PUT /users is not documented")
	}
	if s.OpCount() != 5 {
		t.Errorf("OpCount = %d, want 5", s.OpCount())
	}
	if !s.HasPath("/users/{id}") || s.HasPath("/missing") {
		t.Error("HasPath wrong")
	}
}

const swagger2YAML = `
swagger: "2.0"
basePath: /api/v1
paths:
  /orders:
    get: {}
  /orders/{id}:
    get: {}
`

func TestParseSpec_Swagger2_BasePath(t *testing.T) {
	s, err := ParseSpec([]byte(swagger2YAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Version != "swagger:2" {
		t.Fatalf("version = %q", s.Version)
	}
	// basePath must be prepended.
	if !s.HasOp("GET", "/api/v1/orders") {
		t.Error("basePath not applied to /orders")
	}
	if !s.HasOp("GET", "/api/v1/orders/{id}") {
		t.Error("basePath not applied to /orders/{id}")
	}
}

func TestParseSpec_JSON(t *testing.T) {
	// JSON is valid YAML, so the same parser handles it.
	const j = `{"openapi":"3.0.0","paths":{"/ping":{"get":{}}}}`
	s, err := ParseSpec([]byte(j))
	if err != nil {
		t.Fatalf("parse json: %v", err)
	}
	if !s.HasOp("GET", "/ping") {
		t.Error("JSON spec not parsed")
	}
}

func TestParseSpec_Errors(t *testing.T) {
	cases := map[string]string{
		"empty":         ``,
		"no version":    `paths: {/x: {get: {}}}`,
		"no paths":      `openapi: 3.0.0`,
		"no operations": "openapi: 3.0.0\npaths:\n  /x:\n    parameters: []\n",
		"not yaml/json": "::: not : valid : yaml :::\n\t- broken",
	}
	for name, doc := range cases {
		if _, err := ParseSpec([]byte(doc)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestCanonicalSpecPath(t *testing.T) {
	cases := map[string]string{
		"/users/{userId}":       "/users/{id}",
		"/a/{x}/b/{y}":          "/a/{id}/b/{id}",
		"/static/path":          "/static/path",
		"/trailing/":            "/trailing",
		"":                      "/",
		"no-leading-slash/{id}": "/no-leading-slash/{id}",
	}
	for in, want := range cases {
		if got := canonicalSpecPath(in); got != want {
			t.Errorf("canonicalSpecPath(%q) = %q, want %q", in, got, want)
		}
	}
}
