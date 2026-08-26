package gql

import (
	"strings"
	"testing"
)

func TestParse_NamedQueryWithArgs(t *testing.T) {
	body := []byte(`{"query":"query GetUser { user(id: 42, active: true) { id name } }"}`)
	op, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if op.Type != "query" || op.Name != "GetUser" {
		t.Fatalf("op = %+v, want type=query name=GetUser", op)
	}
	if len(op.TopFields) != 1 || op.TopFields[0].Name != "user" {
		t.Fatalf("TopFields = %+v, want one field named user", op.TopFields)
	}
	args := op.TopFields[0].Args
	if args["id"] != int64(42) {
		t.Errorf("id arg = %v (%T), want int64(42)", args["id"], args["id"])
	}
	if args["active"] != true {
		t.Errorf("active arg = %v, want true", args["active"])
	}
	if got := op.CatalogKey(); got != "query.GetUser" {
		t.Errorf("CatalogKey = %q, want query.GetUser", got)
	}
}

func TestParse_MutationWithVariable(t *testing.T) {
	body := []byte(`{
		"query": "mutation UpdateOrder($orderId: ID!) { updateOrder(id: $orderId, status: \"shipped\") { id } }",
		"variables": {"orderId": "abc-123"}
	}`)
	op, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if op.Type != "mutation" || op.Name != "UpdateOrder" {
		t.Fatalf("op = %+v", op)
	}
	if len(op.TopFields) != 1 {
		t.Fatalf("TopFields = %+v, want 1", op.TopFields)
	}
	if got := op.TopFields[0].Args["id"]; got != "abc-123" {
		t.Errorf("id arg (resolved from $orderId) = %v, want abc-123", got)
	}
	if got := op.TopFields[0].Args["status"]; got != "shipped" {
		t.Errorf("status arg = %v, want shipped", got)
	}
}

func TestParse_AnonymousQuery(t *testing.T) {
	body := []byte(`{"query":"{ me { id } }"}`)
	op, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if op.Name != "" {
		t.Errorf("Name = %q, want empty for an anonymous operation", op.Name)
	}
	if got := op.CatalogKey(); got != "query.anonymous" {
		t.Errorf("CatalogKey = %q, want query.anonymous", got)
	}
}

func TestParse_AliasedField(t *testing.T) {
	body := []byte(`{"query":"{ me: user(id: 1) { name } }"}`)
	op, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(op.TopFields) != 1 {
		t.Fatalf("TopFields = %+v", op.TopFields)
	}
	f := op.TopFields[0]
	if f.Name != "user" {
		t.Errorf("Name = %q, want user (the schema field, not the alias)", f.Name)
	}
	if f.Alias != "me" {
		t.Errorf("Alias = %q, want me", f.Alias)
	}
}

func TestParse_OperationNameSelectsAmongMultiple(t *testing.T) {
	body := []byte(`{
		"query": "query GetUser { user(id: 1) { id } } query GetOrder { order(id: 2) { id } }",
		"operationName": "GetOrder"
	}`)
	op, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if op.Name != "GetOrder" {
		t.Fatalf("Name = %q, want GetOrder", op.Name)
	}
	if len(op.TopFields) != 1 || op.TopFields[0].Name != "order" {
		t.Fatalf("TopFields = %+v, want field 'order'", op.TopFields)
	}
}

func TestParse_MultipleOperationsWithoutNameIsAmbiguous(t *testing.T) {
	body := []byte(`{"query": "query A { a { id } } query B { b { id } }"}`)
	if _, err := Parse(body); err == nil {
		t.Fatal("expected an error: multiple operations with no operationName is ambiguous")
	}
}

func TestParse_UnknownOperationNameErrors(t *testing.T) {
	body := []byte(`{"query": "query A { a { id } }", "operationName": "DoesNotExist"}`)
	if _, err := Parse(body); err == nil {
		t.Fatal("expected an error for an operationName not present in the document")
	}
}

func TestParse_EmptyBodyErrors(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Fatal("expected an error for an empty body")
	}
}

func TestParse_NotJSONErrors(t *testing.T) {
	if _, err := Parse([]byte("not json at all")); err == nil {
		t.Fatal("expected an error for a non-JSON body")
	}
}

func TestParse_MissingQueryFieldErrors(t *testing.T) {
	if _, err := Parse([]byte(`{"operationName": "X"}`)); err == nil {
		t.Fatal("expected an error when the envelope has no query field")
	}
}

func TestParse_MalformedGraphQLSyntaxErrors(t *testing.T) {
	if _, err := Parse([]byte(`{"query": "query { user( { { broken"}`)); err == nil {
		t.Fatal("expected an error for malformed GraphQL syntax")
	}
}

func TestParse_OversizedQueryRejected(t *testing.T) {
	huge := `{"query": "query { user(id: 1) { ` + strings.Repeat("a", maxQueryBytes) + ` } }"}`
	if _, err := Parse([]byte(huge)); err == nil {
		t.Fatal("expected an error for a query over the size cap")
	}
}

func TestParse_UndeclaredVariableOmitsArgRatherThanFailing(t *testing.T) {
	// $missing is referenced but never provided in variables — the whole
	// parse must still succeed; only that one argument is absent.
	body := []byte(`{"query": "query($missing: ID) { user(id: $missing, active: true) { id } }"}`)
	op, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	args := op.TopFields[0].Args
	if _, present := args["id"]; present {
		t.Errorf("id should be absent (unresolved variable), got %v", args["id"])
	}
	if args["active"] != true {
		t.Errorf("active arg = %v, want true (unaffected by the other arg's missing variable)", args["active"])
	}
}

func TestParse_FragmentSpreadAtTopLevelIsSkippedNotFatal(t *testing.T) {
	body := []byte(`{"query": "query { ...Frag } fragment Frag on Query { user(id: 1) { id } }"}`)
	op, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(op.TopFields) != 0 {
		t.Errorf("TopFields = %+v, want empty (fragment spreads skipped in v1)", op.TopFields)
	}
}
