// Package gql parses a GraphQL-over-HTTP request body into a stable
// (operation type, operation name, top-level fields) shape, so the rest of
// the gateway can treat one GraphQL endpoint as many distinct operations
// instead of one opaque "/graphql" blob. See ROADMAP.md B5 for why this
// exists and what still depends on it (DLP/BOLA field- and argument-aware
// wiring are follow-up work, not done here — this package only parses).
//
// Deliberately NOT a full GraphQL server implementation: no schema,
// no validation against types, no execution. Just enough of the query
// language's grammar (via gqlparser, the same parser library the Go GraphQL
// ecosystem's servers use) to answer "which operation is this, and what
// top-level fields/arguments did it ask for" from an unauthenticated,
// untrusted client body.
package gql

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// maxQueryBytes bounds the query string handed to the parser. A GraphQL
// query is client-supplied and unauthenticated at this point in the chain;
// without a cap, a client could submit an arbitrarily large query string and
// spend gateway CPU/memory parsing it before any other control sees the
// request. Generous for legitimate deeply-nested queries, well short of
// a deliberate resource-exhaustion attempt.
const maxQueryBytes = 64 * 1024

// Field is one top-level selection in the operation (e.g. `user` in
// `query { user(id: 42) { name } }`). Nested sub-selections are not
// descended into in v1 — see the package doc.
type Field struct {
	// Name is the field's own name in the schema (what a resolver dispatches
	// on); Alias is what the client called it in the response, which may
	// differ (`me: user(id: 42)`). Alias falls back to Name when unaliased.
	Name  string
	Alias string
	// Args holds each argument's literal value, or the resolved value of a
	// variable reference against the request's `variables` object. Values
	// that reference an undeclared/missing variable are simply omitted
	// (nil, no error) rather than failing the whole parse — a parse failure
	// here must never break passive discovery.
	Args map[string]any
}

// Operation is a single parsed GraphQL operation extracted from a request.
type Operation struct {
	// Type is "query", "mutation", or "subscription".
	Type string
	// Name is empty for an anonymous operation (`{ user(id: 1) { name } }`
	// with no `query OpName { ... }` wrapper).
	Name string
	// TopFields are the operation's top-level selections. Fragment spreads
	// and inline fragments at the top level are skipped in v1 (rare in
	// practice for a request body's root selection set; most clients name
	// their root fields directly).
	TopFields []Field
}

// requestEnvelope is the standard GraphQL-over-HTTP POST body shape
// (https://graphql.org/learn/serving-over-http/).
type requestEnvelope struct {
	Query         string         `json:"query"`
	OperationName string         `json:"operationName"`
	Variables     map[string]any `json:"variables"`
}

// Parse decodes a GraphQL-over-HTTP request body and extracts its operation.
// Returns an error for anything that isn't a well-formed single/selectable
// GraphQL request — callers (the Discovery middleware) treat that as "not
// GraphQL after all" and fall back to the raw path, never as a reason to
// block or alter the request itself.
func Parse(body []byte) (*Operation, error) {
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}
	if len(body) > maxQueryBytes {
		return nil, fmt.Errorf("body exceeds %d bytes", maxQueryBytes)
	}

	var env requestEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decode graphql envelope: %w", err)
	}
	q := strings.TrimSpace(env.Query)
	if q == "" {
		return nil, errors.New("no \"query\" field in body")
	}
	if len(q) > maxQueryBytes {
		return nil, fmt.Errorf("query exceeds %d bytes", maxQueryBytes)
	}

	doc, err := parser.ParseQuery(&ast.Source{Input: q})
	if err != nil {
		return nil, fmt.Errorf("parse graphql query: %w", err)
	}
	if len(doc.Operations) == 0 {
		return nil, errors.New("no operations in document")
	}

	op := doc.Operations[0]
	if env.OperationName != "" {
		found := false
		for _, candidate := range doc.Operations {
			if candidate.Name == env.OperationName {
				op = candidate
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("operationName %q not found in document", env.OperationName)
		}
	} else if len(doc.Operations) > 1 {
		// The spec requires operationName when a document declares multiple
		// operations; a request that omits it here is ambiguous. Rather than
		// guess, decline to parse — the caller falls back to the raw path.
		return nil, errors.New("document has multiple operations but no operationName given")
	}

	fields := make([]Field, 0, len(op.SelectionSet))
	for _, sel := range op.SelectionSet {
		f, ok := sel.(*ast.Field)
		if !ok {
			continue // fragment spread / inline fragment at top level: skip in v1
		}
		alias := f.Alias
		if alias == "" {
			alias = f.Name
		}
		fields = append(fields, Field{Name: f.Name, Alias: alias, Args: argsToMap(f.Arguments, env.Variables)})
	}

	return &Operation{Type: string(op.Operation), Name: op.Name, TopFields: fields}, nil
}

func argsToMap(args ast.ArgumentList, vars map[string]any) map[string]any {
	if len(args) == 0 {
		return nil
	}
	m := make(map[string]any, len(args))
	for _, a := range args {
		// Value.Value resolves variable references against vars and parses
		// literals; it needs no schema/type information (unlike Field.
		// ArgumentMap, which requires a validated Definition we don't have
		// without loading the client's schema — out of scope for v1 parsing).
		// A variable reference with no matching entry in vars and no default
		// resolves to (nil, nil) — not an error — since we skip schema
		// validation; treat that the same as "not provided" rather than
		// recording a misleading literal null.
		v, err := a.Value.Value(vars)
		if err != nil || v == nil {
			continue // a malformed/unresolved argument shouldn't drop the whole op
		}
		m[a.Name] = v
	}
	return m
}

// CatalogKey is a short, stable identifier for the operation, suitable for
// use as (part of) a discovery catalog key: "query.GetUser",
// "mutation.anonymous". Two requests for the same named operation always
// produce the same key regardless of argument values — that's the point:
// it turns "every GraphQL call looks like the same endpoint" into "each
// operation is its own endpoint," the discovery-breadth gap ROADMAP.md B5
// describes.
func (op *Operation) CatalogKey() string {
	name := op.Name
	if name == "" {
		name = "anonymous"
	}
	return op.Type + "." + name
}
