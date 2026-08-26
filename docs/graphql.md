# AEGIS — GraphQL support (v1: discovery + BOLA + DLP attribution)

Where this stands today, what it fixes, and — just as important — what it
does **not** fix yet. See `ROADMAP.md` B5 for the full picture and effort
estimate; this doc is the operational how-to for what's actually shipped.

## The problem this solves

AEGIS's discovery/catalog, DLP classification, and BOLA/BFLA detection
(`internal/discovery`, `internal/middleware`) are all built around the URL
path as the identity of an "endpoint" — `/orders/{id}` is one catalog entry,
`/users/{id}` is another. GraphQL breaks that: every operation goes through
one endpoint (typically `POST /graphql`), and the actual "operation" is
encoded inside the JSON request body (`query { user(id: 42) { ssn } }`), not
the URL. Without doing anything about it, a GraphQL API shows up in AEGIS as
a single opaque endpoint no matter how many distinct queries/mutations a
client actually has.

## What v1 does

`internal/gql` parses a GraphQL-over-HTTP request body (the standard
`{query, operationName, variables}` envelope) using the same parser library
(`vektah/gqlparser`) the Go GraphQL server ecosystem uses — no schema, no
validation, just enough of the grammar to answer "which operation is this."

Set `security.api_inventory.graphql_path` to your GraphQL endpoint's exact
path:

```yaml
security:
  api_inventory:
    enabled: true
    graphql_path: "/graphql"
```

With that set, a `POST /graphql` whose body parses as GraphQL is catalogued
as `/graphql/<operationType>/<operationName>` — e.g.
`/graphql/query/GetUser`, `/graphql/mutation/CreateOrder` — instead of a
single flat `/graphql` entry. An anonymous operation (no `query OpName { }`
wrapper) catalogs as `/graphql/query/anonymous`. Two different named
operations always produce two different catalog entries; the same named
operation always produces the same one, regardless of argument values —
that's deliberate, it's what makes "posture per operation" and "how many
requests did GetUser get" meaningful instead of everything being one bucket.

Leaving `graphql_path` empty (the default) disables all of this — a gateway
that doesn't front GraphQL sees zero behavior change, and the request body is
never even read for this purpose.

**Safety property:** a body that fails to parse (not GraphQL at all, malformed
JSON, ambiguous multi-operation document without `operationName`, or over the
64 KiB parse cap) silently falls back to the plain configured path. This is
passive discovery — a parse miss must never alter, delay meaningfully, or
block the proxied request. The body is peeked and always restored byte-for-
byte before the request reaches the proxy.

### BOLA/BFLA now sees GraphQL traffic

`middleware.AbuseDetection` reads the same `graphql_path` setting (passed
through from `security.api_inventory.graphql_path` — one setting, shared by
both middlewares, so it's declared once). A `POST` to that path has its body
parsed the same way Discovery does, and every top-level field's id-shaped
arguments (`id`, `orderId`, `user_id`, ... — the same naming heuristic
`bodyObjectIDs` already used for JSON bodies) become BOLA candidates exactly
like a path segment, query parameter, or JSON body field already do:

```
query GetUser { user(id: 42) { id name } }
```

tracks as object `42` under scope `/graphql:gql.query.GetUser.user` — scoped
by **operation + field**, not just field name, so two unrelated operations
that happen to both have a field called `user` never share one enumeration
counter or one ownership binding. Enumeration (many distinct IDs from one
consumer), the adaptive baseline, and confirmed single-object ownership
(`owner_fields`, `object_ownership_block`) all apply unchanged — GraphQL
candidates flow into the exact same `TrackObjectAccess`/`TrackObjectOwner`
calls a REST candidate does.

Nothing to configure beyond `graphql_path` itself — this is automatic once
that's set. See `internal/middleware/abuse_test.go`'s `TestAbuseDetection_GraphQLEnumeration`
for a worked example.

## What v1 does NOT do (yet — tracked in ROADMAP.md B5)

- **DLP has no schema-driven field awareness, but per-operation attribution
  already works — verified, not just assumed.** The content-based
  classifiers in `internal/classify` (Luhn-validated card numbers, SSN
  pattern, email regex, ...) scan response bodies regardless of GraphQL vs.
  REST, and DLP enriches the *same* `*discovery.Observation` Discovery seeds
  into the request context — Discovery wraps DLP in the real chain and
  already resolves the per-operation path before DLP runs. So a PII finding
  on `query GetUser { user(id: 42) { ssn } }`'s response lands on the
  `/graphql/query/GetUser` catalog entry today, not a flat `/graphql` bucket
  — no GraphQL-specific DLP code needed
  (`TestDiscovery_GraphQLOperationGetsPIIAttribution`). What's still missing
  is schema-driven awareness: knowing *declaratively* that operation
  `GetUser`'s `ssn` field is PII (vs. discovering it by scanning response
  content after the fact) — that needs schema import, below.
- **Nested fields and fragments are not walked, for BOLA either.** Only top-level selections
  in the chosen operation are extracted (`TestParse_FragmentSpreadAtTopLevelIsSkippedNotFatal`
  documents this). A query built almost entirely from fragments will
  under-report its fields; it will not crash or misattribute.
- **No schema import.** OpenAPI import (`discovery.spec_path`, `PUT
  /api/discovery/spec`) has no GraphQL equivalent — there's no way today to
  upload a client's SDL/introspection result so AEGIS knows which argument is
  an object ID, which field returns PII, or flags an undocumented operation as
  drift. B2's OpenAPI drift/enforcement pattern is the template to follow once
  this is prioritized.
- **WAF/signature coverage is a side effect, not a GraphQL-specific feature.**
  Coraza already inspects `application/json` bodies
  (`jsonBodyDirectives` in `internal/middleware/waf.go`), and a GraphQL
  request body is JSON, so SQLi/XSS-style signature rules already see
  GraphQL variable values. This predates and is independent of `internal/gql`
  — worth knowing so it isn't mistaken for more GraphQL-awareness than exists.

## Verifying it works

```bash
curl -X POST http://localhost:8080/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"query GetUser { user(id: 42) { id name } }"}'
```

Then check the catalog:

```bash
curl -s -H "Authorization: Bearer $AEGIS_ADMIN_SECRET" \
  http://localhost:8081/api/catalog | jq '.[] | select(.path_template | startswith("/graphql"))'
```

Expect a `/graphql/query/GetUser` entry, not a bare `/graphql`.
