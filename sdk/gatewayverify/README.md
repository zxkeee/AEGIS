# gatewayverify — backend verification of AEGIS identity propagation

AEGIS authenticates the caller at the edge and forwards the verified identity to
your backend in `X-Gateway-*` headers. Those headers are only trustworthy if
your backend confirms they were signed by the gateway — otherwise a client that
reaches the backend directly (SSRF, network misconfig, an internal attacker)
could simply set them. This package is the **reference verifier**.

## What the gateway signs

```
payload   = subject ":" roles ":" scopes ":" timestamp ":" nonce
signature = hex( HMAC-SHA256(shared_secret, payload) )
```

Headers set on the upstream request:

| Header                | Meaning                                  |
|-----------------------|------------------------------------------|
| `X-Gateway-Subject`   | authenticated subject (JWT `sub`)        |
| `X-Gateway-Roles`     | comma-separated roles (may be empty)     |
| `X-Gateway-Scopes`    | OAuth2 scopes (may be empty)             |
| `X-Gateway-Timestamp` | unix seconds when signed                 |
| `X-Gateway-Nonce`     | per-request random nonce                 |
| `X-Gateway-Signature` | hex HMAC-SHA256 over the payload         |

The shared secret is the gateway's `auth.secret` (`AEGIS_JWT_SECRET`).

## Three checks (all mandatory)

1. **Authenticity** — the HMAC matches (constant-time compare).
2. **Freshness** — the timestamp is within the allowed window (replay of an old
   capture is rejected).
3. **Replay** — the nonce has not been seen before within the window.

A non-nil error from `Verify` means **reject the request**. Never fall back to
trusting the headers.

## Usage (Go)

```go
import "api-gateway/sdk/gatewayverify"

v := gatewayverify.New(os.Getenv("AEGIS_JWT_SECRET"), 60*time.Second, nil)

mux := http.NewServeMux()
mux.Handle("/", v.Handler(yourHandler)) // 401s anything unsigned/replayed

// inside yourHandler:
id, _ := gatewayverify.FromContext(r)
if !id.HasRole("admin") { http.Error(w, "forbidden", 403); return }
```

Call `Verify(r)` directly if you need the identity without the middleware.

## Scaling out

`New(..., nil)` uses an in-process nonce store — correct for a single instance.
Across a replicated fleet a replay could hit a different instance, so back the
`NonceStore` interface with a shared store (Redis `SET nonce 1 NX EX <ttl>`;
"already exists" ⇒ replay).

## Non-Go backends

Reproduce the three checks in your language:

```python
import hmac, hashlib, time
payload = f"{sub}:{roles}:{scopes}:{ts}:{nonce}".encode()
expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
if not hmac.compare_digest(expected, sig): reject()
if abs(time.time() - int(ts)) > 60:        reject()   # freshness
if nonce_seen_before(nonce):               reject()   # replay
```
