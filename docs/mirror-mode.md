# Mirror mode — observation without touching production traffic

The objection that stops a first pilot is not technical. It is:

> "I am not putting your process in front of my traffic."

It is a fair objection. An inline hop is a new way for someone else's
production to break, and no amount of `observe: true` changes the fact that the
bytes pass through you.

Mirror mode removes the objection by removing the hop. The customer's own proxy
sends a **copy** of each request to AEGIS and discards whatever comes back.
Their traffic never depends on this process — not one byte, not one
millisecond. If AEGIS crashes, hangs, or is stopped, nothing happens to them.

## What you get, and what you do not

| | Mirror mode | Inline (`observe: true`) |
|---|---|---|
| Endpoint catalog, path templates | yes | yes |
| Who calls what (consumer graph) | yes | yes |
| Undocumented / shadow endpoints | yes | yes |
| Authentication present or absent | yes | yes |
| **PII in responses** | **no** | yes |
| **Object-ownership abuse (BOLA)** | **no** | yes |
| Real status codes and latency | **no** | yes |
| Any enforcement | no | no |

The three "no" rows have one cause: **a mirrored request carries no response.**
`ngx_http_mirror_module` and its equivalents duplicate the request only; the
customer's backend answers the original, and AEGIS never sees that answer.
Detecting sensitive data in a response body, or comparing an object's owner
against the caller, both require the body that does not arrive.

This is stated in the catalog rather than inferred. An endpoint observed in
mirror mode records `responses_seen: 0`, so a PII count of zero reads as
"responses were not inspected" and not as "no sensitive data was found". Those
two must never look the same in a document an auditor is shown.

## Configuration

```yaml
mirror_sink: true
observe: true        # required — see below
tls:
  enabled: false     # required — the mirroring proxy already terminated TLS
```

`observe: true` is enforced at startup, not recommended. A mirrored request has
already been answered by the customer's infrastructure, so a control that
"blocks" here stops nothing — it writes a denial into a log about a request that
was served anyway. An operator reading that log would believe an attack was
stopped when it was not, which is worse than having no control.

`tls.enabled: false` for the same class of reason: the mirroring proxy
terminated TLS before copying the request, so there is no ClientHello to
fingerprint. A JA3 value produced here would be this process's own, not the
caller's.

## nginx

```nginx
location /api/ {
    mirror /aegis-mirror;
    mirror_request_body on;       # off if you only need paths and identity
    proxy_pass http://your-backend;
}

location = /aegis-mirror {
    internal;
    proxy_pass http://aegis:8080$request_uri;

    # The client must never wait on the mirror. nginx does not block on it,
    # but keep these tight so a slow AEGIS cannot hold a worker connection.
    proxy_connect_timeout 200ms;
    proxy_read_timeout    500ms;
    proxy_send_timeout    500ms;
}
```

`mirror_request_body off` halves what AEGIS can see (no GraphQL operation
names, no request-body inspection) but removes body duplication entirely. Start
with it off if the customer is nervous; it is the smaller ask.

## Envoy

Use `request_mirror_policies` on the route, pointing at an AEGIS cluster.
Envoy fire-and-forgets the shadow request and ignores its response.

## HAProxy

Use an SPOE agent or a `tcp-request content` mirror, depending on version.

## Verifying it is safe before the customer does

Ask them to run this and watch their own dashboards:

1. Point the mirror at AEGIS. Confirm their p99 is unchanged.
2. **Stop AEGIS entirely.** Confirm their traffic is unaffected — this is the
   demonstration that matters, and it costs them nothing.
3. Start it again. The catalog resumes.

Step 2 is the one to insist on. A claim that a deployment is safe is worth less
than the customer watching it fail with no consequence.

## What it cannot be used for

Do not sell mirror-mode output as a PII or BOLA assessment. It cannot produce
either, and saying otherwise would be the exact failure this product exists to
avoid: claiming more than the evidence supports. Sell it as what it is — a map
of the API surface, who calls it, and what is undocumented — and say plainly
that the response-side findings need an inline pilot.
