<div align="center">

<img src="./docs/assets/logo.png" alt="AEGIS API Protection" width="420" />

# AEGIS — API Protection Gateway

**A high-performance, self-hosted API security gateway and API Security Posture Management (ASPM) platform, written in Go.**

[Overview](#1-overview) ·
[Architecture](#4-architecture) ·
[API Discovery & Posture](#5-api-discovery-and-posture-management) ·
[Configuration](#7-configuration-reference) ·
[Deployment](#9-deployment) ·
[Enterprise Integration](#10-integrating-aegis-into-a-company) ·
[Admin API](#11-admin-api-reference)

</div>

---

> This document is the authoritative technical reference for AEGIS. It is written
> for platform engineers, security engineers, SREs and architects who need to
> understand precisely how the system behaves, how to operate it, and how to
> roll it out across an organisation. An abbreviated Ukrainian translation
> follows the English text (see [Ukrainian / Українська](#ukrainian--українська)).

---

## Table of Contents

1. [Overview](#1-overview)
2. [The Problem Space](#2-the-problem-space)
3. [Design Principles](#3-design-principles)
4. [Architecture](#4-architecture)
   - 4.1 [High-Level Topology](#41-high-level-topology)
   - 4.2 [The Request Lifecycle](#42-the-request-lifecycle)
   - 4.3 [The Middleware Chain](#43-the-middleware-chain)
   - 4.4 [Component Inventory](#44-component-inventory)
   - 4.5 [State and Data Model](#45-state-and-data-model)
   - 4.6 [Concurrency and Performance Model](#46-concurrency-and-performance-model)
   - 4.7 [Configuration Hot-Reload](#47-configuration-hot-reload)
   - 4.8 [Failure Modes and Degradation](#48-failure-modes-and-degradation)
5. [API Discovery and Posture Management](#5-api-discovery-and-posture-management)
   - 5.1 [Passive Discovery](#51-passive-discovery)
   - 5.2 [Path Normalization](#52-path-normalization)
   - 5.3 [The Posture Engine](#53-the-posture-engine)
   - 5.4 [Risk Scoring](#54-risk-scoring)
   - 5.5 [Consumer Analytics](#55-consumer-analytics)
   - 5.6 [Coverage and Effectiveness](#56-coverage-and-effectiveness)
   - 5.7 [Reporting](#57-reporting)
6. [Security Capabilities](#6-security-capabilities)
   - 6.1 [Web Application Firewall](#61-web-application-firewall)
   - 6.2 [Rate Limiting](#62-rate-limiting)
   - 6.3 [Zero-Trust Authentication](#63-zero-trust-authentication)
   - 6.4 [Data Loss Prevention](#64-data-loss-prevention)
   - 6.5 [IP Reputation and Threat Intelligence](#65-ip-reputation-and-threat-intelligence)
   - 6.6 [Bot and Automation Defence](#66-bot-and-automation-defence)
   - 6.7 [Behavioural Scoring and Auto-Ban](#67-behavioural-scoring-and-auto-ban)
   - 6.8 [Active Challenge](#68-active-challenge)
   - 6.9 [Header Hygiene and Identity Propagation](#69-header-hygiene-and-identity-propagation)
7. [Configuration Reference](#7-configuration-reference)
8. [Securing AEGIS Itself](#8-securing-aegis-itself)
9. [Deployment](#9-deployment)
   - 9.1 [Local Binary](#91-local-binary)
   - 9.2 [Docker Compose](#92-docker-compose)
   - 9.3 [Kubernetes and Helm](#93-kubernetes-and-helm)
   - 9.4 [Production Hardening Checklist](#94-production-hardening-checklist)
10. [Integrating AEGIS into a Company](#10-integrating-aegis-into-a-company)
    - 10.1 [Deployment Patterns](#101-deployment-patterns)
    - 10.2 [Phased Rollout](#102-phased-rollout)
    - 10.3 [Sizing and Capacity Planning](#103-sizing-and-capacity-planning)
    - 10.4 [High Availability](#104-high-availability)
    - 10.5 [Identity Provider Integration](#105-identity-provider-integration)
    - 10.6 [Backend Trust and Signature Verification](#106-backend-trust-and-signature-verification)
    - 10.7 [Observability and SIEM Integration](#107-observability-and-siem-integration)
11. [Admin API Reference](#11-admin-api-reference)
12. [Dashboard Guide](#12-dashboard-guide)
13. [Observability](#13-observability)
14. [Performance and Tuning](#14-performance-and-tuning)
15. [Operations Runbook](#15-operations-runbook)
16. [Testing and Continuous Integration](#16-testing-and-continuous-integration)
17. [Troubleshooting](#17-troubleshooting)
18. [Project Layout](#18-project-layout)
19. [Roadmap](#19-roadmap)
20. [Contributing, License and Support](#20-contributing-license-and-support)

---

## 1. Overview

AEGIS is a reverse-proxy security gateway for HTTP APIs. It is deployed inline,
in front of one or more backend services, and applies a configurable chain of
security controls to every inbound request before forwarding it upstream, and to
every response before returning it to the client.

Beyond perimeter enforcement, AEGIS embeds an **API Security Posture Management**
layer. As traffic flows through it, the gateway passively builds and maintains a
catalog of every API endpoint that is actually in use, classifies how well each
endpoint is protected, scores its risk, records which consumers call it, and
exposes that intelligence through an administrative API, a built-in console and
machine-readable reports.

In a single binary, AEGIS combines three product categories that are usually
sold separately:

1. **An API Gateway** — reverse proxy, load balancing, health-aware routing.
2. **A Web Application and API Protection (WAAP) layer** — WAF, rate limiting,
   bot mitigation, IP reputation, data loss prevention, zero-trust authentication.
3. **An API Security Posture Management (ASPM) platform** — discovery, posture,
   risk, consumer analytics and reporting.

AEGIS is self-hosted. There is no external control plane and no mandatory SaaS
dependency. State is kept in Redis (hot path) and PostgreSQL (durable catalog and
forensic history). The system is operated entirely through a YAML configuration
file (with hot-reload) and the administrative API.

### Key facts

| Property | Value |
|---|---|
| Language | Go (module targets Go 1.23+; toolchain 1.25) |
| Runtime dependencies | Redis 7+ (required), PostgreSQL 14+ (optional, enables ASPM and durable forensics) |
| WAF engine | Coraza v3 (OWASP-style rule directives) |
| JWT | golang-jwt v5 with JWKS (keyfunc v3) |
| Default listeners | `:8080` data plane, `:8081` admin plane |
| Configuration | YAML file with environment-variable overrides and hot-reload |
| Packaging | Static binary, Docker image, Helm chart |
| License | MIT |

---

## 2. The Problem Space

Modern organisations expose a large and constantly changing surface of HTTP
APIs: public product APIs, partner integrations, internal microservice APIs,
mobile backends, and machine-to-machine endpoints. This surface is difficult to
secure for several structural reasons:

- **Shadow and zombie APIs.** Endpoints are deployed faster than they are
  documented. Forgotten or undocumented endpoints (shadow APIs) and deprecated
  but still-reachable endpoints (zombie APIs) are a leading cause of breaches
  because no one is watching them.
- **Inconsistent controls.** Authentication, rate limiting and input validation
  are applied per service, by different teams, with different rigour. The result
  is a patchwork in which some endpoints are well protected and others are not,
  with no single source of truth describing which is which.
- **Lack of consumer visibility.** Security teams frequently cannot answer the
  basic question "who is calling this endpoint, and how much?" because that data
  is scattered across service logs.
- **Sensitive data exposure.** APIs return personally identifiable information
  (PII), payment data and secrets. Without an enforcement point that inspects
  responses, leakage is invisible until it is reported externally.
- **Automated abuse.** Credential stuffing, scraping, enumeration and
  volumetric floods target APIs continuously.

AEGIS addresses these problems by being a single, consistent enforcement and
observation point. Because all traffic passes through it, AEGIS can both *apply*
uniform controls and *observe* the real API surface, closing the gap between
"what we think we run" and "what is actually exposed".

---

## 3. Design Principles

AEGIS is built around a small set of explicit principles. Understanding them
makes the rest of the system predictable.

**Inline, ordered, and explicit.** Every request passes through an ordered chain
of middleware. The order is deliberate and documented (see
[Section 4.3](#43-the-middleware-chain)). There is no hidden control flow;
the chain in `cmd/gateway/main.go` is the single description of request handling.

**Fail consciously, not accidentally.** Each control has a defined behaviour
when its backing store is unavailable. Some controls fail open (continue serving)
to preserve availability; others fail closed (deny) to preserve security. These
choices are documented per control in [Section 4.8](#48-failure-modes-and-degradation),
and several are configurable.

**Defence in depth.** Controls overlap intentionally. Spoofed identity headers
are stripped at the edge *and* identity is cryptographically signed before being
passed to the backend. The admin API is protected by a middleware *and* by an
in-handler check on mutating endpoints.

**Observe everything, store deliberately.** AEGIS records security events to a
bounded Redis ring buffer for real-time visibility and, when PostgreSQL is
configured, to durable storage for forensics and reporting. The discovery
pipeline never blocks the request path: observations are enqueued on a
non-blocking channel and aggregated asynchronously.

**Zero-downtime operation.** Configuration changes are applied by atomically
swapping the active handler. In-flight requests are drained on shutdown. There is
no restart required to change routing or security policy.

**Self-contained.** AEGIS does not phone home and requires no proprietary
control plane. Redis and PostgreSQL are the only stateful dependencies, both of
which are standard infrastructure.

---

## 4. Architecture

### 4.1 High-Level Topology

```
                         ┌──────────────────────────────────────────────┐
   Clients / Internet    │                  AEGIS                        │
        │                │                                              │
        │  HTTPS :8080   │   Data plane (reverse proxy + control chain)  │
        ├───────────────►│   ┌────────────────────────────────────┐     │
        │                │   │ middleware chain → load balancer     │     │
        │                │   └────────────────┬───────────────────┘     │
        │                │                    │ signed identity headers   │
        │                │                    ▼                           │
        │                │            Upstream backend services          │
        │                │                                              │
   Operators / SRE       │   Admin plane (REST + console)               │
        │  HTTPS :8081   │   ┌────────────────────────────────────┐     │
        ├───────────────►│   │ AdminAuth → handlers → dashboard     │     │
        │                │   └────────────────────────────────────┘     │
        └────────────────┤                                              │
                         └───────────┬───────────────┬─────────────────┘
                                     │               │
                              ┌──────▼─────┐   ┌─────▼────────┐
                              │   Redis    │   │ PostgreSQL   │
                              │ hot state  │   │ catalog +    │
                              │ counters   │   │ forensics    │
                              └────────────┘   └──────────────┘
```

AEGIS runs two independent HTTP servers in one process:

- **The data plane** on `:8080` proxies and protects production API traffic.
- **The admin plane** on `:8081` serves the management REST API and the console.

These planes must be exposed differently. The data plane faces clients (directly,
or behind a load balancer / ingress). The admin plane must never be exposed to
the public internet; it belongs on a management network or behind a VPN, and is
additionally protected by bearer-token authentication and its own strict rate
limit.

### 4.2 The Request Lifecycle

A request to the data plane proceeds as follows:

1. The Go `http.Server` accepts the connection. Server-level timeouts
   (`ReadHeaderTimeout` 5s, `ReadTimeout` 15s, `WriteTimeout` 30s, `IdleTimeout`
   60s) and `MaxHeaderBytes` (1 MiB) bound resource use and mitigate slow-client
   attacks such as Slowloris.
2. The active handler — an `atomic.Value` holding the current middleware chain —
   is loaded and invoked. This indirection is what enables zero-downtime reload.
3. The request descends the middleware chain in order. Any middleware may
   short-circuit the request (for example, the WAF returning `403`, or the rate
   limiter returning `429`). If it does, the response travels back up the chain
   and is returned to the client without reaching the backend.
4. If the request survives the chain, the reverse proxy selects an upstream via
   the configured load-balancing strategy, applies a per-attempt timeout, and
   forwards the request, adding signed identity headers.
5. The upstream response travels back up the chain. The DLP middleware inspects
   and, if necessary, redacts the body before it leaves the gateway.
6. The discovery middleware records an observation (method, normalized path,
   status, latency, consumer identity, PII flag) without blocking the response.
7. Security-relevant decisions are counted as metrics in Redis and, for blocks,
   written to the forensic log (Redis ring buffer plus PostgreSQL if configured).

### 4.3 The Middleware Chain

The data-plane chain is defined once, in `buildHandlerChain` in
`cmd/gateway/main.go`. The order is significant. The list below is the exact
execution order, outermost (runs first on the way in) to innermost (closest to
the backend):

| # | Middleware | Responsibility | Can block? |
|---|---|---|---|
| 1 | `CleanHeaders` | Strip client-supplied `X-Gateway-*` headers to prevent identity spoofing | No |
| 2 | `SecurityHeaders` | Add response security headers (HSTS, CSP-friendly defaults, `X-Content-Type-Options`, etc.) to every response, including error responses | No |
| 3 | `RequestID` | Assign or propagate `X-Request-ID` for correlation across logs | No |
| 4 | `CORS` | Enforce cross-origin policy; reject disallowed preflights | Yes |
| 5 | `IPGuard` | Static allow/deny lists plus the dynamic Redis blocklist | Yes |
| 6 | `ThreatFeed` | Block IPs present in a periodically refreshed threat-intelligence feed | Yes |
| 7 | `RateLimit` | Per-client fixed-window rate limiting backed by Redis | Yes |
| 8 | `BotProtection` | JA3 fingerprint checks and User-Agent heuristics | Yes |
| 9 | `Challenge` | Active JavaScript challenge for suspicious clients | Yes |
| 10 | `WAF` | Coraza engine applying OWASP-style rules | Yes |
| 11 | `Discovery` | Passive API catalog observation (seeds the observation, captures status and latency) | No |
| 12 | `JWT Auth` | Token validation, JTI revocation, identity propagation | Yes |
| 13 | `DLP` | Response body inspection and PII redaction | No |
| 14 | `BehaviorAnalysis` | Per-IP behavioural risk scoring and auto-ban | Yes |
| — | Reverse proxy | Load balancing, circuit breaking, retry, upstream forwarding | — |

Several ordering decisions are worth calling out:

- **`CleanHeaders` is first.** Internal identity headers (`X-Gateway-Subject`,
  `X-Gateway-Roles`, etc.) must never be trusted from the client. Stripping them
  before anything else runs guarantees that only AEGIS can set them.
- **Cheap, decisive rejections precede expensive analysis.** IP reputation,
  threat feed and rate limiting run before the WAF and before discovery. There is
  no point parsing a request body through the WAF for an IP that is already
  blocked or rate-limited.
- **`Discovery` sits inside the security perimeter but outside authentication.**
  It runs after the WAF and rate limiter (so blocked attack traffic never
  pollutes the API catalog) but wraps the JWT and DLP middleware (so it can
  enrich the observation with the authenticated subject and the PII signal, and
  capture the final response status and latency). Requests that never reach a
  valid route (HTTP 404) are excluded from the catalog.
- **`DLP` wraps the proxy** so it sees the upstream response body and can redact
  it before it leaves the process.

The admin plane has its own, smaller chain: `RequestID`, `SecurityHeaders`,
`AdminAuth`, a strict `RateLimit` (5 requests/second, burst 10), and `CORS`.
`SecurityHeaders` deliberately wraps `AdminAuth` so that `401`/`403` responses
still carry security headers.

### 4.4 Component Inventory

| Package | Responsibility |
|---|---|
| `cmd/gateway` | Process entry point; configuration loading and validation; server lifecycle; handler-chain construction; hot-reload watcher; graceful shutdown |
| `internal/config` | Configuration schema, parsing, environment overrides, and startup validation |
| `internal/middleware` | All request-processing middleware and shared helpers (RealIP resolution, status capture, security headers) |
| `internal/proxy` | Reverse proxy, round-robin load balancer, circuit breaker, retry logic |
| `internal/store` | Redis-backed state: rate counters, blocklists, metrics, behavioural scores, JTI revocation, forensic ring buffer |
| `internal/discovery` | API catalog engine: path normalization, posture engine, risk scoring, consumer aggregation, PostgreSQL persistence |
| `internal/forensic` | Durable forensic-log sink (PostgreSQL) with batched, buffered writes |
| `internal/api` | Admin REST API handlers, server wiring, and the embedded dashboard |
| `internal/logger` | Structured JSON logging |
| `internal/alert` | Alert dispatch (webhook) primitive |

### 4.5 State and Data Model

AEGIS keeps two tiers of state.

**Redis (hot path).** All latency-sensitive state lives in Redis. Keys are
namespaced with a `gw:` prefix:

| Key pattern | Purpose | Lifetime |
|---|---|---|
| `gw:rate:<ip>` | Fixed-window rate counter | Window TTL |
| `gw:blocked_ips` | Set of dynamically blocked IPs | Until removed |
| `gw:metrics:<name>` | Monotonic counters surfaced via the admin API | Persistent |
| `gw:behavior:<ip>:reqs`/`:errs`/`:paths`/`:burst`/`:penalty`/`:score` | Behavioural-scoring inputs | 60s sliding |
| `gw:ja3:<ip>` | Distinct TLS fingerprints observed per IP | 5 min |
| `gw:autoban:<ip>` | Auto-ban violation counter | 10 min |
| `gw:challenge:<ip>` / `gw:challenge_solved:<ip>` | Active-challenge tokens and solved markers | TTL |
| `gw:jwt:revoked:<jti>` | Revoked JWT identifiers | Operator-supplied TTL |
| `gw:forensic_log` | Ring buffer of recent security events (capped at 1000) | Trimmed |

The rate limiter uses a Lua script executed atomically in Redis. It increments
the counter and sets the window expiry **only on the first increment** (or when
the key has lost its TTL). This avoids a subtle defect in the naive
"INCR + EXPIRE on every call" pattern, where continuous traffic perpetually
refreshes the TTL so the window never resets and the client is locked out
permanently.

**PostgreSQL (durable).** When a DSN is configured, AEGIS provisions and uses the
following tables (created automatically on startup):

- `forensic_logs` — every security block event, written in batches by the
  forensic sink. Indexed by timestamp, IP and reason.
- `api_endpoints` — one row per discovered endpoint (method + normalized path
  template), with request/error/auth/anon/PII counts, latency aggregates,
  posture classification, risk score and matched route.
- `api_endpoint_status` — per-endpoint HTTP status distribution, in a separate
  table so concurrent increments sum correctly.
- `api_consumers` — one row per consumer (JWT subject, API key, or IP), with
  request and error counts and first/last-seen timestamps.
- `api_endpoint_consumers` — the consumer-to-endpoint edge with a per-pair call
  count, forming the consumer graph used for analytics.

### 4.6 Concurrency and Performance Model

AEGIS is built on Go's standard `net/http` server, which serves each request on
its own goroutine. The design avoids global locks on the hot path:

- **Trusted proxy CIDRs** are parsed once at startup into an immutable slice, so
  client-IP resolution performs no parsing or locking per request.
- **Rate limiting and behavioural scoring** push all shared state into Redis,
  using pipelines and a server-side Lua script to minimise round trips.
- **The discovery pipeline** is fully asynchronous. The `Discovery` middleware
  constructs an observation and enqueues it on a buffered channel
  (non-blocking; observations are dropped if the buffer is full rather than
  stalling the request). A single background worker aggregates observations into
  per-window maps and flushes them to PostgreSQL every five seconds, using
  upserts that merge deltas. Discovery therefore adds negligible latency to the
  request path and cannot become a bottleneck.
- **The circuit breaker** uses a mutex but only around small critical sections
  that update counters; it is not on a hot loop.

The DLP middleware necessarily buffers response bodies to inspect them. To bound
memory and preserve streaming semantics, it caps the in-memory buffer (default
4 MiB) and transparently switches to pass-through mode for responses that exceed
the cap, for `text/event-stream` responses, and for protocol upgrades
(it implements `http.Flusher` and `http.Hijacker`, so server-sent events and
WebSocket upgrades proxied through the gateway continue to function).

### 4.7 Configuration Hot-Reload

AEGIS watches its configuration file with `fsnotify` (falling back to 5-second
polling if file-system notifications are unavailable). On a change:

1. The new file is parsed.
2. A new middleware chain is built from it.
3. The posture engine is rebuilt so newly observed traffic is classified against
   the new policy.
4. The active handler is replaced via an atomic store.

Because the swap is atomic and in-flight requests continue to use the handler
they started with, configuration changes — including routing changes and
security-policy changes — apply without dropping connections and without a
restart. If the new configuration fails to parse or the chain fails to build, the
previous configuration remains active and the error is logged.

### 4.8 Failure Modes and Degradation

| Dependency / condition | Behaviour |
|---|---|
| Redis unavailable (rate limiter) | Fails open: the request proceeds. This favours availability; for high-assurance deployments a fail-closed mode is on the roadmap. |
| Redis unavailable (IP guard dynamic list) | The dynamic check is skipped and logged; static lists still apply. |
| Redis unavailable (behavioural scoring) | Score resolves to zero and a metric is incremented; traffic is not blocked on a scoring gap. |
| JWKS not yet loaded or permanently unreachable | Fails **closed**: tokens are rejected until keys are available. The gateway never silently falls back to HMAC when a JWKS URL is configured, which would otherwise allow token forgery. |
| PostgreSQL unavailable (forensic sink) | Events are still written to the Redis ring buffer; the durable sink drops events under back-pressure rather than blocking requests. |
| PostgreSQL unavailable (catalog) | Discovery is disabled and the `Discovery` middleware becomes a pass-through; the data plane is unaffected. |
| Upstream failure | The circuit breaker records the failure; retries target other upstreams for idempotent requests; exhausted upstreams yield `503`. |

---

## 5. API Discovery and Posture Management

This is the capability that elevates AEGIS from a protection gateway to an API
security platform. It is implemented in `internal/discovery` and surfaced through
the admin API and the console.

### 5.1 Passive Discovery

Discovery is **passive**: AEGIS learns the API surface from the traffic that
actually flows through it. There is no active scanning and no need to instrument
backends. Every request that passes the security perimeter and reaches a valid
route produces an `Observation` containing the method, the raw path, the response
status, the measured latency, whether a verified identity was present, whether
DLP detected sensitive data in the response, and the consumer identity.

Observations are produced by the `Discovery` middleware and consumed by the
`Catalog` engine on a background goroutine. The engine aggregates them per flush
window and writes rolled-up deltas to PostgreSQL. Because all of this happens off
the request path, discovery is effectively free in terms of client-visible
latency.

Crucially, discovery is positioned so that **attack traffic does not pollute the
catalog**. Requests blocked by IP reputation, the threat feed, the rate limiter,
bot defence or the WAF never reach the discovery middleware. Requests that do not
match any route (404) are explicitly excluded. The catalog therefore reflects the
real, legitimate API surface rather than the noise of internet background
scanning.

### 5.2 Path Normalization

Raw paths contain high-cardinality dynamic segments — numeric identifiers, UUIDs,
opaque tokens. If each distinct value were treated as a separate endpoint, the
catalog would explode in size and an attacker could inflate it by sending random
paths.

AEGIS collapses dynamic segments into a single `{id}` placeholder using
deterministic rules. The following segment types are normalized:

- All-numeric segments (`42` → `{id}`)
- UUIDs (`550e8400-e29b-41d4-a716-446655440000` → `{id}`)
- Long hexadecimal strings (16+ hex characters)
- Long opaque tokens (20+ characters of base64url-style alphabet containing at
  least one digit)

Purely alphabetic segments are preserved, even when long, so genuine resource
names such as `/api/administration/configuration` are not collapsed. The
normalized path plus the HTTP method form the stable catalog key, for example
`GET /api/v1/users/{id}`.

Normalization both stabilises the catalog and provides a structural defence
against cardinality-exhaustion. As an additional safeguard, the store enforces an
upper bound on the number of distinct endpoints and on parameters tracked per
endpoint.

### 5.3 The Posture Engine

Posture answers the question "how well is this endpoint protected?" It is
computed from **configuration**, not from traffic. For each normalized path, the
posture engine finds the most specific matching route (longest path prefix wins)
and resolves the *effective* controls by merging the global security settings with
any per-route overrides.

Per-route overrides are optional and expressed as pointers so that "unset"
(inherit the global setting) is distinct from an explicit `false`. The
overridable controls are `require_auth`, `waf`, `dlp` and `rate_limit`.

Each endpoint is then classified by counting the three core perimeter controls —
authentication required, WAF enabled, and rate limiting enabled:

| Classification | Condition |
|---|---|
| `protected` | All three core controls are effective |
| `partial` | One or two core controls are effective |
| `unprotected` | No core control is effective |
| `shadow` | The endpoint matches no configured route |

DLP, bot defence and IP guard are treated as supplementary signals that
contribute to risk but do not, on their own, move an endpoint out of the
`unprotected` class. Shadow endpoints are inherently the most concerning: the
gateway is observing traffic to a path that the routing configuration does not
acknowledge.

Because posture is derived from configuration, it updates immediately on
hot-reload: changing a route from `require_auth: false` to `true`, or enabling
the WAF globally, reclassifies the affected endpoints on the next flush.

### 5.4 Risk Scoring

Each endpoint carries a 0–100 risk score combining its posture with observed
traffic characteristics. The model is additive and saturating; higher means more
dangerous. The contributing factors are:

- The endpoint is a shadow endpoint (no matching route).
- Authentication is not required.
- The WAF is not effective for the endpoint.
- Rate limiting is not effective for the endpoint.
- DLP is not effective for the endpoint.
- Sensitive data (PII) has been observed in responses — weighted more heavily
  when the endpoint is also unauthenticated.
- Anonymous traffic has been observed on an endpoint that should be
  authenticated.
- A high error ratio, which can indicate probing or abuse.

The score is recomputed from the endpoint's running totals on each aggregation,
so it tracks the current reality of the traffic. The combination of "unprotected
or shadow" with "PII observed" produces the highest scores, which is precisely
the population a security team should triage first.

### 5.5 Consumer Analytics

For every observation, AEGIS derives a consumer identity using the strongest
available signal, in priority order:

1. **JWT subject** (`jwt:<sub>`), taken from the verified token.
2. **API key** (`key:<id>`), from a service-identity header.
3. **Client IP** (`ip:<addr>`), used only when no stronger identity exists, so a
   single caller is not double-counted as both a subject and an IP.

The catalog maintains, per consumer, the total request and error counts and the
set of endpoints touched, and, per consumer-endpoint pair, a call count. This
consumer graph answers operational and security questions directly: who calls a
given endpoint, how much, with what error rate, and which endpoints a given
consumer touches. It is also the foundation on which object-level authorisation
abuse detection (BOLA/BFLA) will be built (see [Roadmap](#19-roadmap)).

### 5.6 Coverage and Effectiveness

The posture summary rolls the catalog up into a coverage view: the count of
endpoints in each posture class, the total, and a coverage percentage (protected
endpoints as a fraction of the total). The top-risk endpoints are surfaced
alongside.

The effectiveness view answers "are the controls actually doing anything?" by
joining the live block counters maintained in Redis with the coverage figure. It
reports, per control (WAF, rate limit, IP guard, behaviour, threat feed, bot,
DLP), how many requests that control has blocked or redacted, the total number of
blocks, and the number of requests that passed the WAF cleanly.

### 5.7 Reporting

The catalog can be exported as a full report through the admin API in either JSON
or CSV. The JSON form includes the posture summary and the full endpoint list;
the CSV form is a flat table suitable for spreadsheets and audit evidence, with
one row per endpoint carrying method, path template, posture, risk score, request
and error counts, authenticated and anonymous counts, PII count, average latency
and last-seen timestamp.

---

## 6. Security Capabilities

### 6.1 Web Application Firewall

The WAF is built on **Coraza v3**, a mature, ModSecurity-compatible engine. AEGIS
ships a curated set of OWASP-style rule directives covering the most common attack
classes:

- SQL injection (keyword-based and boolean/tautology patterns)
- Cross-site scripting (tag/attribute injection and DOM-sink patterns)
- Command injection
- Path traversal and local file inclusion
- Server-side request forgery targeting internal address ranges
- XML external entity injection
- Invalid or unexpected HTTP methods
- Known scanner User-Agents
- Log4Shell / JNDI lookup strings
- HTTP request smuggling via conflicting `Transfer-Encoding`

The WAF operates in two modes selected by `block_mode`: blocking (offending
requests receive `403`/`400`/`405`) or detection-only (requests are logged and
scored but allowed through). For organisations that require the full OWASP Core
Rule Set or custom ModSecurity rules, an external ruleset file can be supplied
via `ruleset_path`, which is loaded in addition to the built-in directives.

Every WAF decision is recorded: blocks increment a metric, add to the offending
IP's behavioural score, write a forensic record, and are surfaced in the console.

### 6.2 Rate Limiting

Rate limiting is per-client (keyed by the resolved real client IP) using a
fixed-window counter in Redis, executed via an atomic Lua script. The window
length, request limit and burst are configurable globally, and the limit can be
overridden per route. Responses carry `X-RateLimit-Limit` and
`X-RateLimit-Remaining`. When the limit is exceeded the gateway returns `429` and
records a forensic event.

The admin plane has its own independent and deliberately strict rate limit
(5 requests/second, burst 10) to resist brute-force attempts against the
management token.

### 6.3 Zero-Trust Authentication

AEGIS validates JSON Web Tokens before forwarding requests. Two validation modes
are supported:

- **Shared-secret (HMAC).** Used when only `secret` is configured. The minimum
  secret length is enforced at startup and known placeholder values are rejected.
- **Asymmetric (JWKS).** When a `jwks_url` is configured, AEGIS fetches and
  caches the issuer's public keys (with retry and backoff) and validates RSA,
  ECDSA and RSA-PSS signatures. This is the recommended production mode and is
  compatible with Auth0, Keycloak, Okta and any standards-compliant provider.

The implementation defends against algorithm-confusion attacks: when JWKS is
configured, HMAC-signed tokens are rejected outright, preventing an attacker from
presenting a token signed with the public key as if it were an HMAC secret. When
JWKS is configured but the keys are not yet loaded or are unreachable, validation
**fails closed** — tokens are rejected rather than silently falling back to HMAC.

Additional validations include issuer and audience checks (when configured) and
**JTI revocation**: a token's `jti` claim is checked against a Redis blocklist,
allowing instant revocation of individual tokens through the admin API. Paths can
be excluded from authentication (for health checks and public endpoints).

### 6.4 Data Loss Prevention

The DLP middleware inspects response bodies and redacts sensitive data before it
reaches the client. Default patterns cover payment card numbers, email addresses
and US social security numbers; operators can supply custom regular expressions.
Matches are replaced with a redaction marker, a metric is incremented, the
discovery observation is flagged as PII-bearing (which feeds risk scoring), and
the event is logged.

DLP is designed not to break legitimate traffic: it bounds its inspection buffer,
falls back to streaming pass-through for large or streaming responses, and
supports protocol upgrades so WebSocket traffic is unaffected.

### 6.5 IP Reputation and Threat Intelligence

`IPGuard` enforces static allow and deny lists from configuration plus a dynamic
blocklist in Redis that other controls (and operators) populate. Allowlisted IPs
bypass the deny checks.

`ThreatFeed` periodically downloads an IP blocklist from a configured HTTPS URL
(HTTPS is enforced to prevent man-in-the-middle injection of the feed), parses
it defensively (bounded download size and entry count), and blocks any client IP
present in the feed. The feed is refreshed on a configurable interval and a
parse error preserves the previous list rather than replacing it with partial
data.

### 6.6 Bot and Automation Defence

`BotProtection` evaluates a TLS JA3 fingerprint supplied in a request header
against a configurable blocklist, tracks fingerprint consistency per IP (a single
IP presenting many distinct fingerprints is suspicious and raises the behavioural
score), and penalises requests with no User-Agent. Because JA3 is consumed from a
header, it is intended for deployments where an upstream TLS-terminating layer
computes and injects the fingerprint; native TLS fingerprinting is on the
roadmap.

### 6.7 Behavioural Scoring and Auto-Ban

`BehaviorAnalysis` computes a per-IP risk score from a sliding window of activity
held in Redis: request volume, error count, path entropy (distinct paths, tracked
with a HyperLogLog), burst activity and accumulated penalties from other controls.
When the score reaches the configured threshold the request is denied; repeated
violations escalate to an automatic, time-bounded IP ban added to the dynamic
blocklist. Scoring is preventive — the score from prior activity is evaluated
*before* the current request is served — and degrades safely to zero if Redis is
unavailable, so a scoring outage never blocks all traffic.

### 6.8 Active Challenge

`Challenge` can interpose a lightweight JavaScript challenge for suspicious
clients. A client that has not solved the challenge receives an HTML page that
issues a token-bearing request; on success the client is marked solved for a
configurable TTL and proceeds normally. This filters trivial scripted clients
that do not execute JavaScript.

### 6.9 Header Hygiene and Identity Propagation

`CleanHeaders` removes any client-supplied `X-Gateway-*` headers at the very edge,
so internal identity headers cannot be spoofed. After successful authentication,
AEGIS propagates the verified identity to the backend as
`X-Gateway-Subject`, `X-Gateway-Roles` and `X-Gateway-Scopes`, and signs the
propagated identity with an HMAC over the subject, roles, scopes, a timestamp and
a per-request nonce, supplied as `X-Gateway-Signature` alongside
`X-Gateway-Timestamp` and `X-Gateway-Nonce`. Backends can verify this signature
to establish that the request genuinely came from AEGIS, check the timestamp for
freshness, and use the nonce to reject replays. See
[Section 10.6](#106-backend-trust-and-signature-verification).

### 6.10 Authorization-Abuse Detection (BOLA / BFLA)

Beyond signature-based input filtering, AEGIS detects authorization abuse — the
class of attack that ordinary WAFs miss because the request itself is well-formed.
This runs after authentication, using the verified subject and roles:

- **BFLA (Broken Function Level Authorization).** Configured privileged path
  prefixes require one of a set of roles; a consumer that calls such a path
  without holding an allowed role is flagged. This catches, for example, a
  non-admin user reaching `/admin/*`.
- **BOLA / IDOR (Broken Object Level Authorization).** AEGIS tracks, per consumer
  and per endpoint, the number of distinct object identifiers accessed within a
  window (using a HyperLogLog to bound memory). A consumer that sweeps an
  unusually large set of object IDs on an endpoint such as `/users/{id}` is
  flagged as enumeration — the canonical IDOR/scraping pattern.

Detection runs in detect-only mode by default (events are recorded and surfaced
in the console and forensic log without disrupting traffic) and can be switched to
block mode per the `security.abuse` configuration. The object-level signal is
built directly on the consumer graph produced by passive discovery.

---

## 7. Configuration Reference

AEGIS reads a single YAML file (default `config/gateway.yaml`, overridable with
`--config`). Sensitive values should be supplied through environment variables,
which override the file. The recognised environment overrides are
`AEGIS_ADMIN_SECRET`, `AEGIS_REDIS_PASSWORD`, `AEGIS_JWT_SECRET` and
`AEGIS_FORENSIC_DSN`.

The configuration is validated at startup. The process refuses to start if, for
example, admin authentication is enabled with a missing, placeholder or
too-short secret; if a wildcard CORS origin is combined with authentication; if a
threat-feed URL is not HTTPS; or if a trusted-proxy entry is not a valid IP or
CIDR.

### Top-level keys

| Key | Type | Description |
|---|---|---|
| `listen` | string | Data-plane listen address (default `:8080`) |
| `admin_listen` | string | Admin-plane listen address (default `:8081`) |
| `admin_auth` | bool | Enable admin bearer-token authentication |
| `admin_secret` | string | Admin bearer token (set via `AEGIS_ADMIN_SECRET`) |
| `forensic_dsn` | string | PostgreSQL DSN; enables durable forensics and the discovery catalog (set via `AEGIS_FORENSIC_DSN`) |
| `trusted_proxies` | list | Exact IPs/CIDRs of trusted reverse proxies for client-IP resolution |
| `tls` | object | TLS termination at the gateway (`enabled`, `cert_file`, `key_file`) |
| `redis` | object | Redis connection (`addr`, `password`, `db`) |
| `logging` | object | `level` and `format` |
| `security` | object | All security controls (see below) |
| `routes` | list | Reverse-proxy routes (see below) |

### `security` block

```yaml
security:
  rate_limit:
    enabled: true
    requests: 100         # requests per window
    window: 60s
    burst_limit: 20
  auth:
    enabled: false
    jwks_url: ""          # preferred for production (RSA/ECDSA)
    secret: ""            # HMAC fallback (set via AEGIS_JWT_SECRET)
    issuer: ""
    audience: ""
    exclude: ["/health", "/public"]
  waf:
    enabled: true
    ruleset_path: ""      # optional external OWASP CRS / ModSecurity rules
    block_mode: true
  bot:
    enabled: true
    blocked_ja3: []
    challenge_mode: false
  behavior:
    enabled: true
    score_threshold: 70
    window_seconds: 60
  ip_guard:
    enabled: true
    whitelist: []
    blacklist: []
    geo_block: []
  dlp:
    enabled: true
    patterns: []          # custom regexes; defaults used when empty
  cors:
    enabled: true
    allow_origins: []     # explicit origins; "*" is rejected with auth enabled
    allow_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allow_headers: ["Content-Type", "Authorization"]
    max_age: 86400
  challenge:
    enabled: false
    ttl: 5m
    score_threshold: 50
  api_inventory:
    enabled: true
    alert_on_new: false
  threat_feed:
    enabled: false
    url: ""               # must be HTTPS
    interval: 1h
```

### `routes` block

Each route forwards a path prefix to one or more upstreams and may override the
global security policy for that prefix:

```yaml
routes:
  - path: "/api/v1/"
    methods: ["GET", "POST", "PUT", "DELETE"]
    upstreams:
      - "http://backend-1:3000"
      - "http://backend-2:3000"
    load_balance: "round_robin"
    timeout: "30s"
    retry_attempts: 2
    strip_prefix: false

  # Fully protected sensitive route (overrides globals)
  - path: "/payments/"
    upstreams: ["http://payments:8080"]
    require_auth: true
    waf: true
    dlp: true
    rate_limit:
      enabled: true
      requests: 50
      window: 60s

  # Deliberately open internal route — appears as "unprotected" in posture
  - path: "/internal/"
    upstreams: ["http://internal:8080"]
    require_auth: false
    waf: false
    rate_limit:
      enabled: false
```

The per-route fields `require_auth`, `waf`, `dlp` and `rate_limit` are optional;
when omitted, the global `security.*` settings apply. These overrides drive both
the runtime behaviour and the posture classification.

---

## 8. Securing AEGIS Itself

A security gateway is a high-value target and must be hardened.

- **Admin plane isolation.** Never expose `:8081` to the public internet. Bind it
  to a management network, place it behind a VPN or service mesh, and restrict it
  with network policy. The admin plane requires a bearer token, validated in
  constant time, and applies its own strict rate limit, but network isolation is
  the primary control.
- **Strong secrets via environment.** The admin secret and JWT secret are
  supplied through environment variables and never committed to the repository.
  Startup validation rejects empty, placeholder and too-short secrets. Generate
  secrets with a cryptographically secure source (for example
  `openssl rand -hex 32`).
- **Authenticated Redis.** Redis holds rate-limit state, blocklists and
  behavioural scores. An unauthenticated Redis reachable on the network is a
  serious risk; startup validation flags an empty Redis password.
- **Header hygiene.** Client-supplied internal identity headers are stripped at
  the edge; backends should additionally verify the gateway signature
  (Section 10.6) and reject direct connections that bypass AEGIS.
- **Defence in depth on mutating admin operations.** Endpoints that change state
  re-check authentication inside the handler, independent of the middleware, so a
  future routing mistake cannot expose them.
- **Transport security.** Terminate TLS at the gateway (`tls` block) or at an
  upstream load balancer. The gateway emits HSTS and related security headers on
  every response.
- **Resource bounds.** Server timeouts and a 1 MiB header cap mitigate
  slow-client and oversized-header attacks; request bodies on admin endpoints are
  size-limited; DLP and threat-feed buffers are bounded.

---

## 9. Deployment

### 9.1 Local Binary

Requirements: Go 1.23+ and a reachable Redis instance.

```bash
go build -o bin/gateway ./cmd/gateway

export AEGIS_ADMIN_SECRET=$(openssl rand -hex 32)
export AEGIS_REDIS_PASSWORD=...            # if Redis requires auth
export AEGIS_FORENSIC_DSN="postgres://user:pass@db-host:5432/aegis?sslmode=require"

./bin/gateway --config config/gateway.yaml
```

The data plane listens on `:8080` and the admin plane on `:8081`. Liveness is
available at `GET /health` and readiness (which checks Redis connectivity) at
`GET /readyz` on the admin plane.

### 9.2 Docker Compose

The repository includes a Compose stack with the gateway, Redis, Prometheus and
Grafana. Secrets are supplied through environment variables (copy `.env.example`
to `.env` and fill in values). Redis is kept off the host network and is reachable
only inside the Compose network.

```bash
cp .env.example .env
# edit .env: AEGIS_ADMIN_SECRET, AEGIS_REDIS_PASSWORD, AEGIS_JWT_SECRET (if used),
#            AEGIS_FORENSIC_DSN (if using an external PostgreSQL), GRAFANA_ADMIN_PASSWORD

docker-compose up -d --build
docker-compose ps
```

To enable the discovery catalog and durable forensics, point `AEGIS_FORENSIC_DSN`
at a PostgreSQL instance. (A PostgreSQL service can be added to the Compose file;
the catalog activates automatically when the DSN is set.)

### 9.3 Kubernetes and Helm

A Helm chart is provided under `charts/aegis`. It includes a Deployment, Service,
ConfigMap, Secret, HorizontalPodAutoscaler and PodDisruptionBudget, with a
hardened pod security context (non-root, read-only root filesystem). Configuration
is delivered via ConfigMap and secrets via a Kubernetes Secret (or an existing
secret you reference).

```bash
kubectl create namespace security

helm install aegis-gateway ./charts/aegis \
  -f ./charts/aegis/values.yaml \
  -n security

kubectl get pods -n security
kubectl logs -n security -l app=aegis-gateway -f
```

The HorizontalPodAutoscaler allows the data plane to scale out under load,
including volumetric attacks; the PodDisruptionBudget preserves availability
during voluntary disruptions. Because all shared state is external (Redis and
PostgreSQL), data-plane pods are stateless and horizontally scalable.

### 9.4 Production Hardening Checklist

- [ ] Admin plane is not reachable from the public internet.
- [ ] `AEGIS_ADMIN_SECRET` is a strong, unique, 32+ character secret.
- [ ] Redis requires authentication and is on a private network.
- [ ] PostgreSQL is configured (`AEGIS_FORENSIC_DSN`) with TLS for durable
      forensics and the catalog.
- [ ] `trusted_proxies` lists the exact IPs/CIDRs of your load balancers only.
- [ ] JWT validation uses `jwks_url` (asymmetric) rather than a shared secret.
- [ ] CORS lists explicit origins; no wildcard with authentication.
- [ ] WAF is in `block_mode` after a detection-only soak period.
- [ ] TLS is terminated at the gateway or at the ingress in front of it.
- [ ] Backends verify the `X-Gateway-Signature` and reject non-AEGIS traffic.
- [ ] Metrics and forensic logs are shipped to your monitoring and SIEM systems.

---

## 10. Integrating AEGIS into a Company

This section describes how to adopt AEGIS across an organisation, from first
deployment to steady-state operation.

### 10.1 Deployment Patterns

AEGIS is deployed **inline** as a reverse proxy. There are three common
placements:

1. **Edge gateway.** AEGIS sits at the perimeter, behind the L4 load balancer or
   ingress, in front of all public APIs. This gives full coverage of
   north-south traffic and is the typical first deployment.
2. **Per-domain or per-team gateway.** A dedicated AEGIS instance fronts a
   specific product domain or team's services, allowing teams to own their
   routing and policy while sharing the platform.
3. **Internal east-west gateway.** AEGIS fronts sensitive internal services
   (for example payments or identity) to bring zero-trust authentication, DLP and
   discovery to service-to-service traffic.

In all patterns, AEGIS terminates the client connection (or receives it from an
upstream TLS terminator) and forwards to backends over the internal network. The
backends should be reachable only through AEGIS.

### 10.2 Phased Rollout

A low-risk adoption proceeds in phases:

1. **Observation (detection-only).** Deploy AEGIS in front of a non-critical
   service with the WAF in detection-only mode (`block_mode: false`),
   authentication disabled or in exclude-heavy mode, and the discovery catalog
   enabled. Let it run long enough to build a representative catalog and to
   observe what the WAF *would* have blocked. This phase produces the first
   posture report: which endpoints exist, which are unprotected, and where PII
   flows.
2. **Tuning.** Use the catalog and the detection-only WAF events to identify
   false positives, add per-route overrides, and define the intended policy. Add
   explicit routes for any shadow endpoints that should exist, and investigate
   those that should not.
3. **Enforcement.** Switch the WAF to `block_mode`, enable rate limiting with
   tuned limits, and turn on authentication for routes that require it (using
   `require_auth` per route). Monitor the effectiveness view to confirm controls
   are blocking real abuse without harming legitimate traffic.
4. **Expansion.** Roll the same pattern out to additional services and teams.
   Standardise on a shared configuration baseline with per-route deviations.
5. **Steady state.** Operate against the posture report: drive the coverage
   percentage up, drive the count of unprotected and shadow endpoints down, and
   triage high-risk endpoints continuously.

### 10.3 Sizing and Capacity Planning

AEGIS is a stateless data plane backed by Redis and PostgreSQL. Capacity is
governed by:

- **CPU** for TLS termination, WAF inspection and proxying. The WAF is the most
  CPU-intensive control; detection-only and block modes have similar cost.
- **Redis throughput** for rate limiting and behavioural scoring. Each request
  performs a small number of Redis operations; size Redis for peak request rate
  with headroom.
- **PostgreSQL write capacity** for forensics and the catalog. Writes are
  batched (forensics) and aggregated over five-second windows (catalog), so the
  database sees far fewer writes than there are requests.

Scale the data plane horizontally behind a load balancer; all instances share
the same Redis and PostgreSQL, so behaviour (rate limits, blocklists, catalog) is
consistent across the fleet.

### 10.4 High Availability

- Run multiple data-plane replicas behind a health-checked load balancer; use the
  `/readyz` probe so unhealthy instances are removed from rotation.
- Use a highly available Redis (replication or cluster). Note that the rate
  limiter currently fails open on Redis unavailability; for high-assurance
  deployments, ensure Redis HA and track the fail-closed mode on the roadmap.
- Use a managed or replicated PostgreSQL. Forensics and the catalog tolerate
  brief database outages (the forensic sink buffers and the catalog drops on
  back-pressure) without affecting the data plane.
- The PodDisruptionBudget and graceful shutdown (30-second drain) preserve
  in-flight requests during rolling updates.

### 10.5 Identity Provider Integration

For production, configure asymmetric JWT validation against your identity
provider's JWKS endpoint:

```yaml
security:
  auth:
    enabled: true
    jwks_url: "https://<tenant>/.well-known/jwks.json"
    issuer: "https://<tenant>/"
    audience: "https://api.example.com"
```

AEGIS fetches and caches the provider's keys and validates RSA/ECDSA signatures,
issuer and audience. To revoke a specific token immediately, post its `jti` to the
admin revocation endpoint; AEGIS rejects it until the supplied TTL expires. Place
health checks and genuinely public endpoints in `auth.exclude`.

### 10.6 Backend Trust and Signature Verification

To complete the zero-trust model, backends should trust identity only when it is
accompanied by a valid gateway signature. After authenticating a request, AEGIS
sets:

- `X-Gateway-Subject`, `X-Gateway-Roles`, `X-Gateway-Scopes` — the propagated
  identity.
- `X-Gateway-Timestamp`, `X-Gateway-Nonce` — freshness and replay inputs.
- `X-Gateway-Signature` — an HMAC-SHA256 over `subject:roles:scopes:timestamp:nonce`
  keyed with the shared secret.

A backend should reconstruct the signed payload, recompute the HMAC with the
shared secret, and reject the request unless the signature matches, the timestamp
is recent (for example within 30 seconds), and the nonce has not been seen before
within the freshness window. Backends should also be network-isolated so they can
only be reached through AEGIS, preventing an attacker from bypassing the gateway
entirely.

### 10.7 Observability and SIEM Integration

AEGIS emits structured JSON logs to standard output, including a per-request
access event (method, normalized path, status, latency, consumer, request ID) and
block events with the reason and offending IP. Ship these logs to your central
logging system. Security block events are also written to PostgreSQL
(`forensic_logs`), which can be queried directly or exported to a SIEM. Operational
counters are available as JSON through the admin API and can be scraped or
forwarded into your metrics stack; native Prometheus exposition and first-class
SIEM connectors are on the roadmap.

---

## 11. Admin API Reference

All `/api/*` endpoints require `Authorization: Bearer <AEGIS_ADMIN_SECRET>` when
admin authentication is enabled. The dashboard (`GET /`) and the probes are
public by design (the dashboard contains no sensitive data; all data loads via
authenticated calls).

| Method | Path | Description |
|---|---|---|
| GET | `/` | Embedded management console (HTML) |
| GET | `/health` | Liveness probe |
| GET | `/readyz` | Readiness probe (verifies Redis connectivity) |
| GET | `/api/metrics` | Operational counters as JSON |
| GET | `/api/config` | Sanitised effective configuration (no secrets) |
| GET | `/api/routes` | Configured routes |
| GET | `/api/block-log` | Recent security block events |
| GET | `/api/inventory` | Legacy endpoint inventory |
| GET | `/api/catalog` | API catalog; filters: `posture`, `q`, `risk`, `limit` |
| GET | `/api/catalog/{id}` | One endpoint with controls, status distribution and consumers |
| GET | `/api/consumers` | Top API consumers; `limit` |
| GET | `/api/posture/summary` | Coverage roll-up and top-risk endpoints |
| GET | `/api/effectiveness` | Blocks per control, total blocks, coverage |
| GET | `/api/report` | Full report; `format=json` (default) or `format=csv` |
| GET | `/api/blocked-ips` | Current dynamic IP blocklist |
| POST | `/api/blocked-ips` | Block an IP (`{"ip": "...", "reason": "..."}`) |
| DELETE | `/api/blocked-ips/{ip}` | Unblock an IP |
| POST | `/api/jwt/revoke` | Revoke a token by `jti` (`{"jti": "...", "ttl_seconds": N}`) |

Mutating endpoints validate the bearer token a second time inside the handler,
size-limit their request bodies, and return errors without leaking internal
detail.

Example — fetch the unprotected endpoints carrying the highest risk:

```bash
curl -s -H "Authorization: Bearer $AEGIS_ADMIN_SECRET" \
  "http://localhost:8081/api/catalog?posture=unprotected&risk=50" | jq .
```

Example — export the posture report as CSV:

```bash
curl -s -H "Authorization: Bearer $AEGIS_ADMIN_SECRET" \
  "http://localhost:8081/api/report?format=csv" -o aegis-api-report.csv
```

---

## 12. Dashboard Guide

The console is served from the admin plane and authenticates with the admin
bearer token entered at login. It is organised into the following views:

- **Overview** — total evaluated traffic, blocked versus passed, discovered
  endpoint count, a live traffic chart and a threat breakdown, and recent
  incidents.
- **Threat Feed** — the complete forensic event log.
- **Analytics** — request volume, blocks by category, top endpoints by request
  count, and an origin breakdown.
- **API Catalog** — the discovered endpoints with posture badges
  (protected/partial/unprotected/shadow), risk score, request counts, PII flag,
  and last-seen time; filterable by posture and path; a row opens a detail panel
  showing effective controls, status distribution and the endpoint's consumers;
  the catalog can be exported to CSV.
- **Posture** — a coverage donut, an effectiveness breakdown of blocks by
  control, and the top-risk endpoints.
- **Consumers** — who calls the APIs, with request volume, error rate, number of
  endpoints touched and last-seen time.
- **API Keys** — authentication-related events.
- **Access Control** — view and manage the dynamic IP blocklist.
- **Settings** — the effective (sanitised) configuration and the routing table.

The console refreshes the active view periodically and reflects the live state of
Redis and the catalog.

---

## 13. Observability

**Logs.** Structured JSON to standard output, with levels (`debug`, `info`,
`warn`, `error`). Each request produces an access event; each block produces a
security event with the reason, IP, path and method. A request ID is assigned and
echoed for cross-system correlation.

**Metrics.** Monotonic counters in Redis, surfaced as JSON via
`GET /api/metrics`. These include total requests passing the WAF, blocks per
control, DLP redactions, bot detections and discovery counters. The Compose stack
ships Prometheus and Grafana for infrastructure metrics; native Prometheus
exposition of the AEGIS counters is on the roadmap.

**Forensics.** Every block is written to a bounded Redis ring buffer for
real-time display and, when PostgreSQL is configured, to the durable
`forensic_logs` table with indexes on timestamp, IP and reason for investigation
and audit.

---

## 14. Performance and Tuning

- **Order matters.** The chain rejects cheaply before it analyses expensively; do
  not reorder controls without understanding the cost implications.
- **WAF cost.** The WAF dominates CPU. If a route does not need it (trusted
  internal traffic), disable it per route to save cycles; the posture view will
  reflect the reduced protection.
- **Rate-limit windows.** Shorter windows react faster but are more sensitive to
  bursts; tune `requests`, `window` and `burst_limit` to your traffic shape, and
  override per route for endpoints with different profiles.
- **DLP buffer.** DLP buffers up to 4 MiB per response; very large JSON responses
  beyond this stream through unredacted. Keep sensitive endpoints' responses
  within the buffer or rely on per-route DLP scoping.
- **Discovery flush.** The catalog flushes every five seconds; the dashboard
  therefore reflects new traffic within seconds, not instantly. The observation
  channel is bounded and drops under extreme load to protect latency.
- **Redis proximity.** Keep Redis close (same availability zone) to minimise
  per-request round-trip latency.

---

## 15. Operations Runbook

**Block an abusive IP immediately.**

```bash
curl -X POST -H "Authorization: Bearer $AEGIS_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"ip":"203.0.113.10","reason":"abuse"}' \
  http://localhost:8081/api/blocked-ips
```

**Revoke a compromised token.**

```bash
curl -X POST -H "Authorization: Bearer $AEGIS_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"jti":"<token-id>","ttl_seconds":86400}' \
  http://localhost:8081/api/jwt/revoke
```

**Change policy without downtime.** Edit the YAML file (or the ConfigMap) and
save. AEGIS detects the change, rebuilds the chain and posture engine, and swaps
the active handler atomically. Verify via the Settings view or `GET /api/config`.

**Investigate an incident.** Query the forensic log via the admin API or, for
historical analysis, query the `forensic_logs` table in PostgreSQL by IP, reason
or time range. Cross-reference with the catalog to see which endpoints the IP
touched.

**Respond to a posture regression.** If coverage drops or a new shadow endpoint
appears, inspect it in the API Catalog, decide whether it should exist, and
either add a protected route for it or remove the backend exposure.

---

## 16. Testing and Continuous Integration

The repository includes unit tests for the discovery package (path normalization
and posture classification) and three GitHub Actions workflows:

- **Tests** — builds and runs the test suite.
- **Lint** — runs `golangci-lint`, installed from source under the project's Go
  toolchain so the linter's Go version never lags behind the module's `go`
  directive.
- **Security** — runs `gosec`, similarly installed under the project toolchain,
  at medium severity so genuine medium and high findings fail the build while
  low-severity noise is filtered.

Build, vet, format and both linters are expected to pass cleanly on every commit
to the main branch. Expanding the test suite — unit coverage of all middleware,
integration tests against Redis and PostgreSQL, and load tests — is the first
roadmap priority.

---

## 17. Troubleshooting

| Symptom | Likely cause | Resolution |
|---|---|---|
| Process exits at startup with a configuration error | Validation rejected the config (weak admin secret, wildcard CORS with auth, non-HTTPS threat feed, invalid trusted proxy) | Read the error message; fix the offending field |
| All clients appear to share one IP | `trusted_proxies` not configured behind a load balancer | List your load balancer IPs/CIDRs in `trusted_proxies` |
| Legitimate traffic is rate-limited as one client | Same as above — client IP resolves to the proxy | Configure `trusted_proxies` |
| Tokens rejected even though they are valid | JWKS not reachable; AEGIS fails closed | Verify `jwks_url`; check egress to the IdP; review logs |
| Catalog is empty | `forensic_dsn` not set, or only 404/blocked traffic seen | Set `AEGIS_FORENSIC_DSN`; confirm requests reach valid routes |
| WebSocket/SSE endpoints break | A middleware buffering the response | DLP supports streaming and upgrades; ensure the route reaches the proxy and check for an upstream issue |
| CI Lint/Security fail with a Go version error | Tooling Go older than the module's `go` directive | The workflows install tools via `go install` under the project toolchain to avoid this |

---

## 18. Project Layout

```
.
├── cmd/gateway/            Entry point, lifecycle, chain construction, hot-reload
├── internal/
│   ├── api/                Admin REST API and embedded dashboard
│   ├── config/             Configuration schema, parsing, validation
│   ├── discovery/          API catalog: normalization, posture, risk, consumers, PG
│   ├── forensic/           Durable forensic-log sink (PostgreSQL)
│   ├── logger/             Structured JSON logging
│   ├── middleware/         Security middleware chain and helpers
│   ├── proxy/              Reverse proxy, load balancing, circuit breaker
│   └── store/              Redis-backed hot state
├── charts/aegis/           Helm chart (Deployment, Service, HPA, PDB, Secret, ...)
├── config/gateway.yaml     Example configuration
├── docs/                   Documentation and assets
├── Dockerfile              Multi-stage build
├── docker-compose.yml      Local stack (gateway, Redis, Prometheus, Grafana)
└── ROADMAP.md              Product roadmap
```

---

## 19. Roadmap

The detailed, prioritised roadmap lives in [ROADMAP.md](./ROADMAP.md). In summary,
the path from a strong implementation to a commercial product runs through:
proving reliability (comprehensive tests and CI gates); real console identity
(RBAC, SSO, MFA) and multi-tenancy; the flagship detection capability — OWASP API
Top-10 abuse detection starting with object-level authorisation (BOLA/BFLA) built
on the existing consumer graph; integrations (SIEM, alerting, OpenAPI drift); and
out-of-band deployment and high-availability hardening.

---

## 20. Contributing, License and Support

Contributions are welcome. Please read `CONTRIBUTING.md` before opening a pull
request. Report security issues privately through the repository's security
advisory mechanism rather than in public issues; see `SECURITY.md`.

AEGIS is released under the MIT License; see `LICENSE`.

---

## Appendix A — Complete Annotated Configuration

The following is a complete, production-oriented configuration with every key
annotated. Secrets are intentionally left blank and supplied via environment
variables.

```yaml
# ─────────────────────────────────────────────────────────────────────────────
# AEGIS — gateway configuration
# Sensitive values (admin_secret, redis.password, auth.secret, forensic_dsn) are
# supplied via environment variables and override anything set here.
# ─────────────────────────────────────────────────────────────────────────────

listen: ":8080"            # Data-plane (proxy) listen address.
admin_listen: ":8081"      # Admin-plane listen address. Never expose publicly.

admin_auth: true           # Require a bearer token on /api/* admin endpoints.
admin_secret: ""           # Set via AEGIS_ADMIN_SECRET (>= 32 chars). Blank here.

# PostgreSQL DSN. Enables durable forensic logs AND the API discovery catalog.
# Set via AEGIS_FORENSIC_DSN. When empty, discovery is disabled and forensics
# are kept only in the Redis ring buffer.
forensic_dsn: ""

# Exact IPs/CIDRs of the reverse proxies in front of AEGIS. Only addresses listed
# here are trusted to set X-Forwarded-For. Leave empty to always use the raw TCP
# peer address (the safest default when there is no proxy).
trusted_proxies: []        # e.g. ["10.10.1.5/32", "10.10.1.6/32"]

tls:
  enabled: false           # Terminate TLS at the gateway. Often handled upstream.
  cert_file: ""
  key_file: ""

redis:
  addr: "localhost:6379"
  password: ""             # Set via AEGIS_REDIS_PASSWORD. Required in production.
  db: 0

logging:
  level: "info"            # debug | info | warn | error
  format: "json"

security:
  rate_limit:
    enabled: true
    requests: 100          # Allowed requests per window, per client IP.
    window: 60s
    burst_limit: 20        # Allowance above the steady rate.

  auth:
    enabled: false         # Enable JWT validation on the data plane.
    jwks_url: ""           # Preferred for production (RSA/ECDSA). Asymmetric.
    secret: ""             # HMAC fallback. Set via AEGIS_JWT_SECRET (>= 32 chars).
    issuer: ""             # Optional issuer (iss) check.
    audience: ""           # Optional audience (aud) check.
    exclude:               # Paths that bypass authentication entirely.
      - "/health"
      - "/public"

  waf:
    enabled: true
    ruleset_path: ""       # Optional external OWASP CRS / ModSecurity rules file.
    block_mode: true       # true = block offending requests; false = detect only.

  bot:
    enabled: true
    blocked_ja3: []        # JA3 fingerprints to block outright.
    challenge_mode: false

  behavior:
    enabled: true
    score_threshold: 70    # Risk score (0-100) at which a request is denied.
    window_seconds: 60

  ip_guard:
    enabled: true
    whitelist: []          # Always-allowed IPs (bypass deny checks).
    blacklist: []          # Always-blocked IPs.
    geo_block: []          # Reserved for geo policy.

  dlp:
    enabled: true
    patterns: []           # Custom regexes. Defaults (cards, email, SSN) if empty.

  cors:
    enabled: true
    allow_origins: []      # Explicit origins. "*" is rejected when auth enabled.
    allow_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allow_headers: ["Content-Type", "Authorization"]
    max_age: 86400

  challenge:
    enabled: false
    ttl: 5m
    score_threshold: 50

  api_inventory:
    enabled: true          # Enable passive discovery (requires forensic_dsn).
    alert_on_new: false    # Fire an alert when a new endpoint is first seen.

  threat_feed:
    enabled: false
    url: ""                # Must be HTTPS.
    interval: 1h

routes:
  - path: "/api/v1/"
    methods: ["GET", "POST", "PUT", "DELETE"]
    upstreams:
      - "http://backend-1:3000"
      - "http://backend-2:3000"
    load_balance: "round_robin"
    timeout: "30s"
    retry_attempts: 2
    strip_prefix: false

  - path: "/payments/"
    upstreams: ["http://payments:8080"]
    require_auth: true
    waf: true
    dlp: true
    rate_limit:
      enabled: true
      requests: 50
      window: 60s
```

## Appendix B — Metrics Catalog

The following monotonic counters are maintained in Redis and surfaced as JSON via
`GET /api/metrics`. They are the raw inputs to the dashboard's Overview,
Analytics, Posture and Effectiveness views.

| Metric | Meaning |
|---|---|
| `requests_passed_waf` | Requests inspected by the WAF and allowed through |
| `waf_blocked` | Requests blocked by a WAF rule |
| `blocked_rate_limit_exceeded` | Requests denied by the rate limiter |
| `blocked_ip_blacklisted` | Requests denied by the static IP blacklist |
| `blocked_ip_blocked_dynamic` | Requests denied by the dynamic Redis blocklist |
| `blocked_behavior_high_risk` | Requests denied by behavioural scoring |
| `blocked_threat_feed_blocked` | Requests denied by the threat-intelligence feed |
| `blocked_admin_no_auth` | Admin requests rejected for missing authentication |
| `blocked_admin_bad_secret` | Admin requests rejected for an invalid token |
| `bot_ja3_blocked` | Requests blocked by a JA3 fingerprint match |
| `bot_ja3_inconsistent` | IPs flagged for presenting inconsistent fingerprints |
| `bot_empty_ua` | Requests observed with no User-Agent |
| `dlp_redacted` | Responses in which DLP redacted sensitive data |
| `api_new_endpoint` | First-time discoveries of an endpoint |
| `api_new_parameter` | First-time discoveries of a query parameter |
| `behavior_autoban` | Automatic IP bans triggered by behavioural escalation |

(Internal error counters such as `behavior_score_redis_error` and
`forensic_marshal_error` are also incremented to make backing-store failures
observable.)

## Appendix C — Glossary

- **ASPM (API Security Posture Management).** The discipline of inventorying APIs,
  assessing how well each is protected, and continuously reducing risk.
- **Shadow API.** An endpoint that is reachable and in use but is not acknowledged
  by the routing configuration.
- **Posture.** The classification of an endpoint's protection level
  (`protected`, `partial`, `unprotected`, `shadow`).
- **Consumer.** An identified caller of an API, derived from a JWT subject, an API
  key, or a client IP.
- **Path template.** A normalized path in which dynamic segments are replaced by
  `{id}`, used as a stable catalog key.
- **JA3.** A fingerprint of a TLS client computed from the ClientHello, used to
  identify automated clients.
- **JTI.** The unique identifier claim of a JWT, used here for revocation.
- **Fail open / fail closed.** Behaviour when a backing store is unavailable:
  continue serving (open) versus deny (closed).
- **Inline deployment.** A placement in which the gateway is on the request path
  and can both observe and enforce.

## Appendix D — Frequently Asked Questions

**Does AEGIS require PostgreSQL?** No. Redis is required. PostgreSQL is optional
but strongly recommended: it enables the discovery catalog and durable forensic
history. Without it, AEGIS still proxies and protects, and keeps recent forensics
in Redis.

**Does discovery slow down requests?** No measurably. Observations are enqueued on
a non-blocking channel and aggregated by a background worker; they are dropped
under extreme load rather than stalling the request path.

**Can I run multiple replicas?** Yes. The data plane is stateless; all shared
state is in Redis and PostgreSQL, so rate limits, blocklists and the catalog are
consistent across replicas.

**How do I make an endpoint show as protected?** Ensure the three core controls —
authentication, WAF and rate limiting — are effective for it, either globally or
via per-route overrides (`require_auth`, `waf`, `rate_limit`).

**Why is my endpoint shown as shadow?** Traffic is reaching a path that matches no
configured route. Either add a route for it or remove the backend exposure.

**Is the dashboard safe to expose?** The dashboard HTML is static and carries no
secrets, but the admin plane as a whole must not be public: all data loads through
authenticated `/api/*` calls, and the admin token must be protected.

**How do I revoke a token immediately?** Post its `jti` to `/api/jwt/revoke`. AEGIS
rejects it until the supplied TTL expires.

---
---

# Ukrainian / Українська

<div align="center">

<img src="./docs/assets/logo.png" alt="AEGIS API Protection" width="420" />

# AEGIS — Шлюз захисту API

**Високопродуктивний, self-hosted шлюз безпеки API та платформа управління
станом безпеки API (ASPM), написана мовою Go.**

</div>

> Це авторитетна технічна документація AEGIS. Її призначено для інженерів
> платформ, інженерів безпеки, SRE та архітекторів, яким потрібно точно
> розуміти, як поводиться система, як її експлуатувати та як розгорнути її в
> межах організації. Нижче наведено переклад англійського тексту.

## Зміст

1. [Огляд](#1-огляд)
2. [Проблематика](#2-проблематика)
3. [Принципи проєктування](#3-принципи-проєктування)
4. [Архітектура](#4-архітектура)
5. [Виявлення API та управління станом безпеки](#5-виявлення-api-та-управління-станом-безпеки)
6. [Можливості безпеки](#6-можливості-безпеки)
7. [Довідник конфігурації](#7-довідник-конфігурації)
8. [Захист самого AEGIS](#8-захист-самого-aegis)
9. [Розгортання](#9-розгортання)
10. [Впровадження AEGIS у компанії](#10-впровадження-aegis-у-компанії)
11. [Довідник Admin API](#11-довідник-admin-api)
12. [Посібник з панелі](#12-посібник-з-панелі)
13. [Спостережуваність](#13-спостережуваність)
14. [Продуктивність і тюнінг](#14-продуктивність-і-тюнінг)
15. [Операційний посібник](#15-операційний-посібник)
16. [Тестування та CI](#16-тестування-та-ci)
17. [Усунення несправностей](#17-усунення-несправностей)
18. [Структура проєкту](#18-структура-проєкту)
19. [Дорожня карта](#19-дорожня-карта)
20. [Внесок, ліцензія та підтримка](#20-внесок-ліцензія-та-підтримка)

## 1. Огляд

AEGIS — це reverse-proxy шлюз безпеки для HTTP API. Він розгортається inline,
перед одним або кількома бекенд-сервісами, і застосовує конфігурований ланцюг
заходів безпеки до кожного вхідного запиту перед його пересиланням на бекенд та
до кожної відповіді перед поверненням клієнту.

Окрім захисту периметра, AEGIS містить шар **управління станом безпеки API
(ASPM)**. У міру проходження трафіку шлюз пасивно будує та підтримує каталог
кожного API-ендпойнта, який реально використовується, класифікує рівень захисту
кожного ендпойнта, оцінює його ризик, фіксує, які споживачі до нього звертаються,
і надає цю інформацію через адміністративний API, вбудовану консоль та
машиночитні звіти.

В одному бінарному файлі AEGIS поєднує три категорії продуктів, які зазвичай
продаються окремо:

1. **API-шлюз** — reverse proxy, балансування навантаження, маршрутизація з
   урахуванням стану бекендів.
2. **Шар захисту вебзастосунків і API (WAAP)** — WAF, обмеження частоти,
   протидія ботам, репутація IP, запобігання витоку даних, zero-trust
   автентифікація.
3. **Платформа управління станом безпеки API (ASPM)** — виявлення, стан безпеки,
   ризик, аналітика споживачів та звітність.

AEGIS є self-hosted. Немає зовнішньої панелі керування та обов'язкової залежності
від SaaS. Стан зберігається в Redis (гарячий шлях) та PostgreSQL (довговічний
каталог та історія форензики). Система керується повністю через файл конфігурації
YAML (з гарячим перезавантаженням) та адміністративний API.

### Ключові факти

| Властивість | Значення |
|---|---|
| Мова | Go (модуль націлений на Go 1.23+; toolchain 1.25) |
| Залежності середовища | Redis 7+ (обов'язково), PostgreSQL 14+ (опційно, вмикає ASPM і довговічну форензику) |
| Рушій WAF | Coraza v3 (директиви правил у стилі OWASP) |
| JWT | golang-jwt v5 з JWKS (keyfunc v3) |
| Слухачі за замовчуванням | `:8080` площина даних, `:8081` площина адміністрування |
| Конфігурація | Файл YAML з перевизначенням через змінні середовища та гарячим перезавантаженням |
| Пакування | Статичний бінарний файл, образ Docker, чарт Helm |
| Ліцензія | MIT |

## 2. Проблематика

Сучасні організації відкривають велику та постійно змінювану поверхню HTTP API:
публічні продуктові API, партнерські інтеграції, внутрішні API мікросервісів,
бекенди мобільних застосунків та ендпойнти machine-to-machine. Цю поверхню важко
захистити з кількох структурних причин:

- **Тіньові та «зомбі» API.** Ендпойнти розгортаються швидше, ніж документуються.
  Забуті чи незадокументовані ендпойнти (тіньові API) та застарілі, але все ще
  доступні ендпойнти (зомбі-API) є провідною причиною витоків, бо за ними ніхто
  не стежить.
- **Непослідовні заходи контролю.** Автентифікація, обмеження частоти та
  валідація вводу застосовуються по-різному різними командами. Результат —
  «клаптикова ковдра», де частина ендпойнтів захищена добре, а частина — ні, без
  єдиного джерела істини.
- **Брак видимості споживачів.** Команди безпеки часто не можуть відповісти на
  базове питання «хто звертається до цього ендпойнта і як часто?».
- **Витік чутливих даних.** API повертають персональні дані (PII), платіжну
  інформацію та секрети. Без точки контролю, що інспектує відповіді, витік
  невидимий, доки про нього не повідомлять ззовні.
- **Автоматизовані зловживання.** Credential stuffing, скрейпінг, перебір та
  об'ємні флуди постійно атакують API.

AEGIS вирішує ці проблеми, будучи єдиною узгодженою точкою контролю та
спостереження. Оскільки весь трафік проходить через нього, AEGIS може як
*застосовувати* однорідні заходи контролю, так і *спостерігати* реальну поверхню
API, закриваючи розрив між «що, на нашу думку, ми запускаємо» та «що реально
відкрито».

## 3. Принципи проєктування

**Inline, упорядковано та явно.** Кожен запит проходить упорядкований ланцюг
middleware. Порядок є навмисним і задокументованим. Прихованого потоку керування
немає; ланцюг у `cmd/gateway/main.go` — це єдиний опис обробки запитів.

**Збій усвідомлений, а не випадковий.** Кожен контроль має визначену поведінку,
коли його сховище недоступне. Одні контролі дають збій «у відкриту» (продовжують
обслуговування) задля доступності; інші — «у закриту» (відмова) задля безпеки.

**Глибокий захист.** Контролі навмисно перекриваються. Підроблені заголовки
ідентичності видаляються на межі *та* ідентичність криптографічно підписується
перед передачею на бекенд.

**Спостерігати за всім, зберігати свідомо.** AEGIS записує події безпеки до
обмеженого кільцевого буфера Redis для видимості в реальному часі та, коли
налаштовано PostgreSQL, до довговічного сховища для форензики та звітності.
Конвеєр виявлення ніколи не блокує шлях запиту.

**Робота без простоїв.** Зміни конфігурації застосовуються атомарною заміною
активного обробника. Запити «в польоті» завершуються під час зупинки.

**Самодостатність.** AEGIS не «телефонує додому» і не потребує пропрієтарної
панелі керування. Redis і PostgreSQL — єдині залежності зі станом.

## 4. Архітектура

AEGIS запускає два незалежні HTTP-сервери в одному процесі: **площину даних** на
`:8080`, що проксіює та захищає продакшн-трафік API, та **площину
адміністрування** на `:8081`, що обслуговує керівний REST API та консоль. Площину
адміністрування ніколи не можна відкривати в публічний інтернет; її місце — в
керівній мережі або за VPN, додатково захищена автентифікацією за bearer-токеном
та власним суворим обмеженням частоти.

**Життєвий цикл запиту.** Сервер `net/http` приймає з'єднання з обмеженнями на
рівні сервера (тайм-аути та обмеження розміру заголовків) для пом'якшення атак
повільних клієнтів. Активний обробник (зберігається в `atomic.Value`)
завантажується та викликається — саме ця непрямість уможливлює перезавантаження
без простою. Запит спускається ланцюгом middleware по порядку; будь-який
middleware може коротко замкнути запит. Якщо запит «виживає», reverse proxy
обирає бекенд за стратегією балансування, застосовує тайм-аут на спробу та
пересилає запит, додаючи підписані заголовки ідентичності. Відповідь бекенда
повертається вгору ланцюгом; middleware DLP інспектує та за потреби редагує тіло
перед виходом зі шлюзу. Middleware виявлення фіксує спостереження, не блокуючи
відповідь.

**Ланцюг middleware** (зовнішній → внутрішній): `CleanHeaders`,
`SecurityHeaders`, `RequestID`, `CORS`, `IPGuard`, `ThreatFeed`, `RateLimit`,
`BotProtection`, `Challenge`, `WAF`, `Discovery`, `JWT Auth`, `DLP`,
`BehaviorAnalysis`, далі reverse proxy. Ключові рішення щодо порядку: `CleanHeaders`
йде першим, щоб внутрішні заголовки ідентичності ніколи не приймалися від клієнта;
дешеві рішучі відмови (репутація IP, threat feed, обмеження частоти) передують
дорогому аналізу (WAF); `Discovery` розташований усередині периметра безпеки, але
ззовні автентифікації, щоб атакувальний трафік не засмічував каталог, але
спостереження могло бути збагачене автентифікованим суб'єктом і сигналом PII.

**Стан.** Гарячий стан — у Redis з префіксом ключів `gw:` (лічильники частоти,
списки блокувань, метрики, поведінкові оцінки, відкликання JTI, кільцевий буфер
форензики). Обмежувач частоти використовує атомарний Lua-скрипт, що встановлює
термін дії вікна лише при першому інкременті, уникаючи дефекту, за якого
безперервний трафік нескінченно оновлює TTL. Довговічний стан — у PostgreSQL:
`forensic_logs`, `api_endpoints`, `api_endpoint_status`, `api_consumers`,
`api_endpoint_consumers`.

**Модель паралельності.** Дизайн уникає глобальних блокувань на гарячому шляху:
CIDR довірених проксі парсяться один раз при старті; обмеження частоти та
поведінкова оцінка виносять стан у Redis; конвеєр виявлення повністю асинхронний
(спостереження ставляться в чергу в буферизований канал, фоновий воркер агрегує
та скидає в PostgreSQL кожні п'ять секунд).

**Гаряче перезавантаження.** AEGIS стежить за файлом конфігурації через
`fsnotify`. При зміні новий ланцюг будується, рушій стану безпеки
перебудовується, і активний обробник замінюється атомарно — без розриву з'єднань
і без перезапуску. Якщо нова конфігурація не парситься, попередня залишається
активною.

**Режими збою.** Обмежувач частоти при недоступності Redis дає збій «у відкриту»;
поведінкова оцінка зводиться до нуля; валідація JWT при налаштованому JWKS, якщо
ключі не завантажені або недосяжні, дає збій **«у закриту»** — токени
відхиляються, шлюз ніколи не переходить непомітно на HMAC.

## 5. Виявлення API та управління станом безпеки

Це можливість, що підносить AEGIS від шлюзу захисту до платформи безпеки API.

**Пасивне виявлення.** AEGIS вивчає поверхню API з трафіку, що реально через
нього проходить. Немає активного сканування й потреби інструментувати бекенди.
Кожен запит, що пройшов периметр безпеки та досяг дійсного маршруту, породжує
спостереження. Спостереження обробляються у фоновій горутині й записуються
агрегованими дельтами в PostgreSQL. Атакувальний трафік не засмічує каталог:
запити, заблоковані репутацією IP, threat feed, обмежувачем частоти, захистом від
ботів чи WAF, не досягають middleware виявлення; запити без відповідного маршруту
(404) явно виключаються.

**Нормалізація шляхів.** Динамічні сегменти (числові ідентифікатори, UUID,
непрозорі токени) згортаються в єдиний заповнювач `{id}` за детермінованими
правилами. Це стабілізує каталог і захищає від вичерпання кардинальності.
Нормалізований шлях плюс метод HTTP утворюють стабільний ключ каталогу,
наприклад `GET /api/v1/users/{id}`.

**Рушій стану безпеки.** Стан безпеки обчислюється з **конфігурації**. Для кожного
шляху рушій знаходить найбільш специфічний маршрут і визначає *ефективні*
контролі, об'єднуючи глобальні налаштування з перевизначеннями на рівні маршруту
(`require_auth`, `waf`, `dlp`, `rate_limit`). Класифікація за трьома основними
контролями периметра (автентифікація, WAF, обмеження частоти): `protected` (усі
три), `partial` (один-два), `unprotected` (жодного), `shadow` (немає маршруту).

**Оцінка ризику.** Кожен ендпойнт має оцінку ризику 0–100, що поєднує стан
безпеки з характеристиками трафіку: тіньовий ендпойнт, відсутність
автентифікації/WAF/обмеження частоти/DLP, спостережувані PII (вагоміше для
неавтентифікованих), анонімний трафік на ендпойнті, що має бути автентифікованим,
висока частка помилок. Поєднання «незахищений або тіньовий» зі «спостережуваними
PII» дає найвищі оцінки.

**Аналітика споживачів.** Для кожного спостереження виводиться ідентичність
споживача за найсильнішим доступним сигналом: суб'єкт JWT, далі ключ API, далі IP
(лише за відсутності сильнішої ідентичності). Граф споживачів відповідає на
питання, хто звертається до ендпойнта, як часто та з якою часткою помилок, і є
основою для майбутнього виявлення зловживань авторизацією на рівні об'єктів
(BOLA/BFLA).

**Покриття та ефективність.** Зведення стану безпеки дає вигляд покриття:
кількість ендпойнтів у кожному класі та відсоток покриття. Вигляд ефективності
поєднує лічильники блокувань Redis із покриттям, повідомляючи по кожному контролю
кількість заблокованих чи відредагованих запитів.

**Звітність.** Каталог експортується повним звітом через адмін-API у JSON або CSV
(плаский рядок на ендпойнт, придатний для аудиту).

## 6. Можливості безпеки

**WAF.** Побудований на Coraza v3. Постачається з набором директив у стилі OWASP:
SQL-ін'єкції, XSS, ін'єкції команд, обхід шляхів/LFI, SSRF до внутрішніх діапазонів,
XXE, недійсні методи HTTP, відомі User-Agent сканерів, Log4Shell/JNDI, контрабанда
HTTP-запитів. Працює в режимі блокування або лише виявлення (`block_mode`).
Зовнішній файл правил (повний OWASP CRS) можна підkey через `ruleset_path`.

**Обмеження частоти.** На клієнта (за реальним IP) з фіксованим вікном у Redis
через атомарний Lua-скрипт. Налаштовується глобально та перевизначається на
маршрут. Площина адміністрування має власне суворе обмеження.

**Zero-trust автентифікація.** Валідація JWT перед пересиланням: спільний секрет
(HMAC) або асиметричний (JWKS, рекомендовано для продакшну). Захист від атак
плутанини алгоритмів; при налаштованому JWKS HMAC-токени відхиляються; якщо ключі
ще не завантажені або недосяжні — збій «у закриту». Перевірки emitента та
аудиторії; відкликання JTI через Redis уможливлює миттєве відкликання токенів.

**DLP.** Інспектує тіла відповідей і редагує чутливі дані (платіжні картки,
email, SSN за замовчуванням; власні regex). Обмежує буфер і коректно працює зі
стрімінгом та оновленнями протоколу (WebSocket).

**Репутація IP та threat intelligence.** Статичні списки дозволу/заборони плюс
динамічний список у Redis; `ThreatFeed` періодично завантажує список IP з URL
через HTTPS (примусово) з обмеженнями розміру.

**Захист від ботів.** Перевірка JA3-відбитка із заголовка за списком блокування,
відстеження узгодженості відбитків на IP, штраф за відсутній User-Agent.

**Поведінкова оцінка та авто-бан.** Оцінка ризику на IP зі змінного вікна
активності в Redis; при досягненні порогу запит відхиляється, повторні порушення
ескалюються до автоматичного тимчасового бану IP. Оцінювання превентивне й
безпечно деградує до нуля при недоступності Redis.

**Активний виклик.** Легкий JavaScript-виклик для підозрілих клієнтів відсіює
тривіальні скриптовані клієнти, що не виконують JavaScript.

**Гігієна заголовків та поширення ідентичності.** `CleanHeaders` видаляє надані
клієнтом заголовки `X-Gateway-*` на межі. Після автентифікації AEGIS поширює
ідентичність як `X-Gateway-Subject/Roles/Scopes` і підписує її HMAC над
суб'єктом, ролями, scopes, міткою часу та nonce (`X-Gateway-Signature` разом із
`X-Gateway-Timestamp` та `X-Gateway-Nonce`).

## 7. Довідник конфігурації

AEGIS читає єдиний файл YAML (за замовчуванням `config/gateway.yaml`,
перевизначається через `--config`). Чутливі значення слід надавати через змінні
середовища: `AEGIS_ADMIN_SECRET`, `AEGIS_REDIS_PASSWORD`, `AEGIS_JWT_SECRET`,
`AEGIS_FORENSIC_DSN`. Конфігурація валідується при старті: процес відмовляється
стартувати, якщо, наприклад, увімкнено адмін-автентифікацію з відсутнім чи надто
коротким секретом; якщо wildcard CORS поєднано з автентифікацією; якщо URL
threat-feed не HTTPS; або якщо запис trusted-proxy не є дійсним IP/CIDR.

Маршрути (`routes`) пересилають префікс шляху на один або кілька бекендів і можуть
перевизначати глобальну політику безпеки для цього префікса через опційні поля
`require_auth`, `waf`, `dlp`, `rate_limit`. Ці перевизначення керують як
поведінкою під час виконання, так і класифікацією стану безпеки. Повний приклад
наведено в англійській частині (розділ 7).

## 8. Захист самого AEGIS

Шлюз безпеки є цінною мішенню й має бути загартований. Ключові заходи: ізоляція
площини адміністрування від публічного інтернету; сильні секрети через змінні
середовища (валідація відхиляє порожні, плейсхолдери та надто короткі); Redis з
автентифікацією в приватній мережі; гігієна заголовків плюс перевірка підпису
шлюзу на бекендах; повторна перевірка автентифікації всередині обробників
мутуючих операцій; завершення TLS на шлюзі або ingress; обмеження ресурсів
(тайм-аути, обмеження заголовків і тіл, буферів DLP та threat-feed).

## 9. Розгортання

**Локальний бінарний файл.** Потрібні Go 1.23+ та досяжний Redis. Зберіть
`go build -o bin/gateway ./cmd/gateway`, задайте змінні середовища та запустіть із
`--config`. Площина даних — `:8080`, адміністрування — `:8081`; liveness на
`GET /health`, readiness (перевіряє Redis) на `GET /readyz`.

**Docker Compose.** Репозиторій містить стек зі шлюзом, Redis, Prometheus і
Grafana. Секрети надаються через змінні середовища (скопіюйте `.env.example` в
`.env`). Redis недосяжний з мережі хоста. Щоб увімкнути каталог виявлення та
довговічну форензику, вкажіть `AEGIS_FORENSIC_DSN` на інстанс PostgreSQL.

**Kubernetes і Helm.** Чарт у `charts/aegis` містить Deployment, Service,
ConfigMap, Secret, HorizontalPodAutoscaler та PodDisruptionBudget із загартованим
контекстом безпеки пода (non-root, read-only кореневу ФС). HPA дозволяє площині
даних масштабуватися під навантаженням; оскільки весь стан зовнішній, поди площини
даних є stateless і горизонтально масштабованими.

**Чек-лист загартування продакшну:** площина адміністрування недосяжна публічно;
сильний `AEGIS_ADMIN_SECRET`; Redis з автентифікацією в приватній мережі;
налаштовано PostgreSQL; `trusted_proxies` містить лише ваші балансувальники;
валідація JWT через `jwks_url`; явні origins CORS; WAF у `block_mode` після
періоду лише-виявлення; завершення TLS; бекенди перевіряють `X-Gateway-Signature`;
метрики та форензика передаються в моніторинг і SIEM.

## 10. Впровадження AEGIS у компанії

**Шаблони розгортання.** AEGIS розгортається inline як reverse proxy: як крайовий
шлюз на периметрі; як шлюз на домен/команду; як внутрішній east-west шлюз перед
чутливими сервісами. У всіх шаблонах бекенди мають бути досяжні лише через AEGIS.

**Поетапне впровадження.** (1) Спостереження: розгорніть із WAF лише-виявлення та
увімкненим каталогом, щоб побудувати репрезентативний каталог і перший звіт стану
безпеки. (2) Тюнінг: за каталогом і подіями WAF визначте хибні спрацювання,
додайте перевизначення на маршрут, дослідіть тіньові ендпойнти. (3) Примусове
застосування: перемкніть WAF у `block_mode`, увімкніть обмеження частоти й
автентифікацію для потрібних маршрутів, стежте за виглядом ефективності. (4)
Розширення на інші сервіси та команди. (5) Усталений режим: підвищуйте відсоток
покриття, знижуйте кількість незахищених і тіньових ендпойнтів, безперервно
сортуйте високоризикові.

**Розмір та планування потужності.** Потужність визначається CPU (TLS, WAF,
проксіювання), пропускною здатністю Redis та потужністю запису PostgreSQL (записи
батчуються та агрегуються). Масштабуйте площину даних горизонтально за
балансувальником; усі інстанси спільно використовують Redis і PostgreSQL.

**Висока доступність.** Кілька реплік площини даних за балансувальником із
перевіркою `/readyz`; високодоступний Redis (зважайте, що обмежувач частоти наразі
дає збій «у відкриту»); кероване чи реплікаване PostgreSQL; PodDisruptionBudget і
м'яке завершення (30 с) зберігають запити «в польоті».

**Інтеграція з провайдером ідентичності.** Для продакшну налаштуйте асиметричну
валідацію JWT за JWKS-ендпойнтом вашого IdP (`jwks_url`, `issuer`, `audience`).
Для миттєвого відкликання токена надішліть його `jti` на ендпойнт відкликання.

**Довіра бекендів і перевірка підпису.** Бекенди мають довіряти ідентичності лише
за наявності дійсного підпису шлюзу: реконструювати підписане навантаження,
переобчислити HMAC спільним секретом, відхилити, якщо підпис не збігається, мітка
часу не свіжа або nonce вже бачено. Бекенди мають бути мережево ізольовані.

**Спостережуваність та інтеграція з SIEM.** AEGIS видає структуровані JSON-логи в
stdout (подія доступу на запит, події блокування). Передавайте логи в центральну
систему. Події блокування також пишуться в PostgreSQL (`forensic_logs`).
Операційні лічильники доступні як JSON через адмін-API.

## 11. Довідник Admin API

Усі ендпойнти `/api/*` потребують `Authorization: Bearer <AEGIS_ADMIN_SECRET>`,
коли увімкнено адмін-автентифікацію. Панель (`GET /`) та проби публічні за задумом.
Перелік ендпойнтів: `/health`, `/readyz`, `/api/metrics`, `/api/config`,
`/api/routes`, `/api/block-log`, `/api/inventory`, `/api/catalog`,
`/api/catalog/{id}`, `/api/consumers`, `/api/posture/summary`,
`/api/effectiveness`, `/api/report` (`format=json|csv`), `/api/blocked-ips`
(GET/POST), `/api/blocked-ips/{ip}` (DELETE), `/api/jwt/revoke` (POST). Мутуючі
ендпойнти перевіряють токен повторно всередині обробника, обмежують розмір тіла й
не розкривають внутрішніх деталей у помилках.

## 12. Посібник з панелі

Консоль обслуговується з площини адміністрування й автентифікується адмін-токеном.
Вигляди: **Overview** (загальний трафік, заблоковано/пропущено, кількість
ендпойнтів, графік трафіку, інциденти); **Threat Feed** (повний журнал форензики);
**Analytics** (обсяг запитів, блокування за категоріями, топ ендпойнтів);
**API Catalog** (виявлені ендпойнти з бейджами стану безпеки, ризиком, прапорцем
PII; фільтрація; панель деталей з ефективними контролями, розподілом статусів і
споживачами; експорт CSV); **Posture** (донат покриття, ефективність, топ ризику);
**Consumers** (хто звертається до API); **API Keys** (події автентифікації);
**Access Control** (динамічний список блокувань IP); **Settings** (ефективна
конфігурація та таблиця маршрутизації).

## 13. Спостережуваність

**Логи:** структурований JSON у stdout із рівнями; кожен запит породжує подію
доступу, кожне блокування — подію безпеки; призначається ID запиту для кореляції.
**Метрики:** монотонні лічильники в Redis, доступні як JSON через
`GET /api/metrics`. **Форензика:** кожне блокування пишеться в обмежений кільцевий
буфер Redis та, за наявності PostgreSQL, у довговічну таблицю `forensic_logs` з
індексами для розслідувань і аудиту.

## 14. Продуктивність і тюнінг

Порядок має значення (ланцюг відмовляє дешево перед дорогим аналізом); WAF домінує
за CPU (вимикайте на маршрут для довіреного внутрішнього трафіку); налаштовуйте
вікна обмеження частоти під форму трафіку; DLP буферизує до 4 МіБ на відповідь
(понад це — стрімить без редагування); каталог скидається кожні п'ять секунд;
тримайте Redis поруч для мінімізації затримки на запит.

## 15. Операційний посібник

Негайно заблокувати IP: `POST /api/blocked-ips`. Відкликати скомпрометований
токен: `POST /api/jwt/revoke`. Змінити політику без простою: відредагуйте YAML
(або ConfigMap) — AEGIS виявить зміну, перебудує ланцюг і рушій стану безпеки та
атомарно замінить обробник. Розслідувати інцидент: запитайте журнал форензики
через адмін-API або таблицю `forensic_logs` за IP/причиною/часом, звіривши з
каталогом. Реагувати на регресію стану безпеки: дослідіть ендпойнт у каталозі,
вирішіть, чи має він існувати, і або додайте захищений маршрут, або приберіть
відкриття бекенда.

## 16. Тестування та CI

Репозиторій містить юніт-тести для пакета виявлення (нормалізація шляхів і
класифікація стану безпеки) та три робочі процеси GitHub Actions: **Tests**
(збірка та тести), **Lint** (`golangci-lint`, встановлений з джерел під toolchain
проєкту), **Security** (`gosec` середньої серйозності). Збірка, vet, форматування
та обидва лінтери мають проходити чисто на кожному коміті в основну гілку.
Розширення набору тестів — перший пріоритет дорожньої карти.

## 17. Усунення несправностей

Поширені випадки: процес завершується при старті з помилкою конфігурації
(валідація відхилила конфіг — прочитайте повідомлення, виправте поле); усі клієнти
здаються одним IP (не налаштовано `trusted_proxies` за балансувальником); токени
відхиляються попри валідність (JWKS недосяжний, AEGIS дає збій «у закриту»);
каталог порожній (не задано `forensic_dsn` або бачено лише 404/заблокований
трафік); ендпойнти WebSocket/SSE ламаються (перевірте, що маршрут досягає проксі);
CI Lint/Security падає з помилкою версії Go (робочі процеси встановлюють
інструменти через `go install` під toolchain проєкту, щоб цього уникнути).

## 18. Структура проєкту

Структура збігається з англійською частиною (розділ 18): `cmd/gateway` (точка
входу, життєвий цикл, побудова ланцюга, гаряче перезавантаження); `internal/api`
(адмін-API і панель), `internal/config` (схема, парсинг, валідація),
`internal/discovery` (каталог: нормалізація, стан безпеки, ризик, споживачі, PG),
`internal/forensic` (довговічний sink форензики), `internal/logger`,
`internal/middleware`, `internal/proxy`, `internal/store`; `charts/aegis` (чарт
Helm); `config/gateway.yaml`; `docs/`; `Dockerfile`; `docker-compose.yml`;
`ROADMAP.md`.

## 19. Дорожня карта

Детальну пріоритезовану дорожню карту наведено в [ROADMAP.md](./ROADMAP.md).
Стисло, шлях від міцної реалізації до комерційного продукту пролягає через:
доведення надійності (тести та CI-гейти); справжню ідентичність консолі (RBAC,
SSO, MFA) і мультитенантність; флагманську можливість виявлення — виявлення
зловживань OWASP API Top-10, починаючи з авторизації на рівні об'єктів
(BOLA/BFLA) на основі наявного графа споживачів; інтеграції (SIEM, сповіщення,
дрейф OpenAPI); розгортання out-of-band і загартування високої доступності.

## 20. Внесок, ліцензія та підтримка

Внески вітаються. Прочитайте `CONTRIBUTING.md` перед відкриттям pull request. Про
проблеми безпеки повідомляйте приватно через механізм security advisory
репозиторію, а не в публічних issue; див. `SECURITY.md`. AEGIS випущено за
ліцензією MIT; див. `LICENSE`.
