# Changelog — gatewayverify

All notable changes to the reference identity-verification SDK. The wire format
is a contract between the AEGIS gateway and the backends that verify its signed
identity headers; a change here **requires the gateway and every backend to be
on a compatible version**.

## Unreleased

### Changed — BREAKING (signature payload v2)

The canonical HMAC payload gained the ownership-identity claim:

```
v1:  sub ":" roles ":" scopes ":" ts ":" nonce
v2:  sub ":" roles ":" scopes ":" identity ":" ts ":" nonce
```

**Why:** `X-Gateway-Identity` (the object-ownership claim used for BOLA checks)
was forwarded to backends but was **not** covered by the signature, so a backend
reachable directly by clients could be tricked into trusting a forged value. It
is now authenticated and exposed as `Identity.Identity`.

**Impact:** a v2 gateway and a v1 backend (or vice-versa) will **fail every
request** — the reconstructed payload differs, so the HMAC never matches and
`Verify` returns `ErrBadSignature` (401). There is intentionally no
accept-both-formats fallback: honouring the old format would reintroduce a
downgrade path in a security primitive.

**Upgrade:** rebuild all backends against this SDK version and deploy them
together with the gateway. When `identity_claim` is unset the identity segment
is empty on both sides, so the only observable change is the new `Identity`
field.
