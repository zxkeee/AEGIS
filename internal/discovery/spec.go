package discovery

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Spec is the documented API surface parsed from an OpenAPI 3.x or Swagger 2.0
// document. Only the path/method inventory is retained — drift detection needs
// the documented operation set, not the full schema — so a single minimal
// parser (no heavy OpenAPI dependency) covers both versions.
//
// Every documented path is canonicalised through the same NormalizePath used on
// live traffic (and template parameters such as {userId} are collapsed to the
// catalog's {id} placeholder) so that documented and observed endpoints compare
// apples-to-apples.
type Spec struct {
	Version string // "openapi:3" | "swagger:2"
	// ops is the set of documented operations keyed by "METHOD /template".
	ops map[string]bool
	// methodsByPath maps a canonical path template to the set of documented
	// methods, so an undocumented *method* on a documented *path* can be told
	// apart from a wholly undocumented path.
	methodsByPath map[string]map[string]bool
}

// httpMethods are the OpenAPI operation keys treated as HTTP methods on a path
// item. Other keys (parameters, summary, $ref, servers, …) are ignored.
var httpMethods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"options": true, "head": true, "patch": true, "trace": true,
}

// specDoc is the minimal shape we decode from an OpenAPI/Swagger document. YAML
// v3 also decodes JSON (JSON is a subset of YAML), so one path covers both
// `.yaml` and `.json` specs.
type specDoc struct {
	OpenAPI  string                          `yaml:"openapi"`
	Swagger  string                          `yaml:"swagger"`
	BasePath string                          `yaml:"basePath"` // Swagger 2.0 only
	Paths    map[string]map[string]yaml.Node `yaml:"paths"`
}

// ParseSpec parses an OpenAPI 3.x or Swagger 2.0 document into a Spec. It accepts
// YAML or JSON. An empty document, or one with no usable paths, is an error so a
// misconfigured spec fails loudly rather than silently reporting "everything is
// undocumented".
func ParseSpec(raw []byte) (*Spec, error) {
	if len(raw) == 0 {
		return nil, errors.New("spec: empty document")
	}
	var doc specDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("spec: parse: %w", err)
	}

	version := ""
	switch {
	case strings.HasPrefix(doc.OpenAPI, "3."):
		version = "openapi:3"
	case strings.HasPrefix(doc.Swagger, "2."):
		version = "swagger:2"
	default:
		return nil, errors.New("spec: not an OpenAPI 3.x or Swagger 2.0 document (missing/unsupported openapi/swagger version)")
	}
	if len(doc.Paths) == 0 {
		return nil, errors.New("spec: document declares no paths")
	}

	s := &Spec{
		Version:       version,
		ops:           map[string]bool{},
		methodsByPath: map[string]map[string]bool{},
	}
	// Swagger 2.0 prefixes every path with basePath; OpenAPI 3 folds the base
	// into server URLs, which we deliberately ignore (the gateway sees paths
	// relative to its own mount, not the upstream's declared servers).
	base := ""
	if version == "swagger:2" {
		base = strings.TrimRight(doc.BasePath, "/")
	}

	for rawPath, item := range doc.Paths {
		tmpl := canonicalSpecPath(base + rawPath)
		for method := range item {
			m := strings.ToLower(strings.TrimSpace(method))
			if !httpMethods[m] {
				continue
			}
			M := strings.ToUpper(m)
			s.ops[M+" "+tmpl] = true
			if s.methodsByPath[tmpl] == nil {
				s.methodsByPath[tmpl] = map[string]bool{}
			}
			s.methodsByPath[tmpl][M] = true
		}
	}
	if len(s.ops) == 0 {
		return nil, errors.New("spec: document declares paths but no HTTP operations")
	}
	return s, nil
}

// canonicalSpecPath converts a documented path template into the catalog's
// canonical form: every `{param}` segment becomes the `{id}` placeholder, then
// the whole path is run through NormalizePath so documented and observed
// templates are byte-identical for matching.
func canonicalSpecPath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") && len(s) >= 2 {
			segs[i] = placeholder
		}
	}
	return NormalizePath(strings.Join(segs, "/"))
}

// HasOp reports whether the exact METHOD+template is documented.
func (s *Spec) HasOp(method, template string) bool {
	if s == nil {
		return false
	}
	return s.ops[strings.ToUpper(method)+" "+template]
}

// HasPath reports whether the path template is documented under any method.
func (s *Spec) HasPath(template string) bool {
	if s == nil {
		return false
	}
	return s.methodsByPath[template] != nil
}

// OpCount is the number of documented operations.
func (s *Spec) OpCount() int {
	if s == nil {
		return 0
	}
	return len(s.ops)
}

// operations returns the documented operations as sorted (method, template)
// pairs for deterministic drift output.
func (s *Spec) operations() []specOp {
	out := make([]specOp, 0, len(s.ops))
	for tmpl, methods := range s.methodsByPath {
		for m := range methods {
			out = append(out, specOp{Method: m, Template: tmpl})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Template != out[j].Template {
			return out[i].Template < out[j].Template
		}
		return out[i].Method < out[j].Method
	})
	return out
}

type specOp struct {
	Method, Template string
}
