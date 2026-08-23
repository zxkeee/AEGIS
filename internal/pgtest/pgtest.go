// Package pgtest isolates PostgreSQL-backed integration tests by schema.
//
// `go test ./...` runs packages in PARALLEL, and all our integration tests
// point at the single database in POSTGRES_DSN. Several packages TRUNCATE the
// same tables (admin_users, api_endpoints, admin_audit_log, …) for a clean
// slate, so without isolation one package's TRUNCATE wipes another's rows
// mid-test and both flake. Rather than serialise the whole suite with `-p 1`
// (which slows CI and hides real regressions) or leave a footgun for anyone who
// runs `go test ./...` locally against a DB, each package routes its objects
// into its own schema via search_path — created here, torn down on cleanup.
package pgtest

import (
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// DSN returns POSTGRES_DSN rewritten so every connection this package opens
// resolves and creates tables inside the dedicated schema `schema` (via the
// libpq startup parameter search_path), isolating it from every other test
// package that shares the same database. It skips the test when POSTGRES_DSN is
// unset, keeping the default `go test ./...` hermetic. The schema is dropped
// and recreated so each run starts clean; a t.Cleanup drops it afterwards.
func DSN(t *testing.T, schema string) string {
	t.Helper()
	base := os.Getenv("POSTGRES_DSN")
	if base == "" {
		t.Skip("POSTGRES_DSN not set; skipping PostgreSQL integration test")
	}

	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatalf("pgtest: open base DSN: %v", err)
	}
	defer func() { _ = admin.Close() }()
	q := pgx.Identifier{schema}.Sanitize()
	// Fresh schema per run: drops any tables a previous run left with an older
	// column set, so schema-migrating DDL in the stores starts from clean.
	if _, err := admin.Exec("DROP SCHEMA IF EXISTS " + q + " CASCADE"); err != nil {
		t.Fatalf("pgtest: drop schema %s: %v", schema, err)
	}
	if _, err := admin.Exec("CREATE SCHEMA " + q); err != nil {
		t.Fatalf("pgtest: create schema %s: %v", schema, err)
	}
	t.Cleanup(func() {
		db, err := sql.Open("pgx", base)
		if err != nil {
			return
		}
		defer func() { _ = db.Close() }()
		_, _ = db.Exec("DROP SCHEMA IF EXISTS " + q + " CASCADE")
	})

	return withSearchPath(t, base, schema)
}

// withSearchPath adds `search_path=<schema>` to the DSN. pgx forwards it as a
// startup parameter, so every pooled connection lands in the schema. Handles
// both URL DSNs (postgres://…) and libpq keyword/value DSNs.
func withSearchPath(t *testing.T, base, schema string) string {
	t.Helper()
	if strings.Contains(base, "://") {
		u, err := url.Parse(base)
		if err != nil {
			t.Fatalf("pgtest: parse DSN: %v", err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		return u.String()
	}
	return base + " search_path=" + schema
}
