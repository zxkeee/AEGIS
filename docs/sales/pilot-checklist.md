# Running the first pilot

From "yes" to a delivered report. Written to be followed literally, because the
first one will happen while you are nervous.

## Before you touch anything

**Get these in writing.** Email is enough; a contract is not needed yet.

- [ ] Permission to run the mirror, from someone who can give it.
- [ ] Which environment, and the traffic volume you should expect.
- [ ] Whether they want `mirror_request_body on` or `off`. **Offer `off` by
      default** — it means bodies never reach you, which shortens the
      conversation with their lawyer and costs you only GraphQL operation names.
- [ ] Who to contact if something looks wrong, and how fast.
- [ ] Permission to name them, or explicit refusal. Ask now; asking after the
      report feels like a price increase.

**Say the limits out loud before they are discovered:**

- No PII findings, no object-ownership findings, no status codes. Mirror carries
  no response.
- The report is signed with a key **you** generate. It proves the document was
  not altered after it was produced. It does not prove anything about you — an
  auditor would want a third party for that, and there is not one.

That second point will cost you nothing with an engineer and buys everything if
they later ask a sharp question about it.

## Their side

One nginx block. Give them this, not a document to interpret:

```nginx
location /api/ {
    mirror /aegis-mirror;
    mirror_request_body off;      # on only if they agreed to it
    proxy_pass http://their-backend;
}

location = /aegis-mirror {
    internal;
    proxy_pass http://aegis-host:8080$request_uri;
    proxy_connect_timeout 200ms;
    proxy_read_timeout    500ms;
    proxy_send_timeout    500ms;
}
```

See `docs/mirror-mode.md` for Envoy and HAProxy.

## Your side

```yaml
mirror_sink: true
observe: true
tls:
  enabled: false
forensic_dsn: "postgres://..."     # required, or nothing is retained
security:
  api_inventory: { enabled: true }
  consumer_id:   { enabled: true, headers: ["X-API-Key", "Authorization"] }
```

Both flags are enforced at startup. Without `observe` the gateway refuses to
start, because a control that "blocks" a mirrored copy blocks nothing and logs a
denial for a request that was served anyway.

## Day one, in front of them

Do all three while they watch. Ten minutes.

1. **Mirror on.** Their p99 on their own dashboard. Unchanged.
2. **Stop AEGIS completely.** Their traffic is unaffected. *This is the
   demonstration.* Insist on it even if they do not ask.
3. **Start it again.** The catalog resumes.

Anyone still nervous after step 2 is nervous about something else — find out
what, because it is the real objection.

## Week one

- [ ] Endpoints appearing in `/api/catalog`.
- [ ] Path templates sane. `/users/{id}` and not one row per user id — if the
      learner has not collapsed something, tell them before they notice.
- [ ] Consumers resolving to subjects or keys, not to `ip:` for everything. All
      `ip:` means `consumer_id.headers` does not match what they actually send.
- [ ] Volume plausible against their own request counts. An order of magnitude
      off means the mirror is only seeing part of the traffic.

## Week three — what you hand over

1. **The map.** Every endpoint, method, path template, first and last seen,
   request count.
2. **What is not in their spec.** If they have an OpenAPI document, upload it
   and let drift do the work. If they do not, that is itself the finding — and
   the most common one.
3. **Who calls what.** Per consumer. Expect at least one "wait, what is *that*
   service doing there".
4. **Unauthenticated reach.** Endpoints called with no identity at all. Not a
   vulnerability claim — an observation, phrased as one.
5. **The signed report**, plus `reportverify` and the key id, so they can check
   it themselves. Show them the check once.

## The question that decides the next step

Ask it at handover, in these words:

> Что из этого вы бы показали аудитору, и чего вам не хватило?

Their answer is worth more than the pilot. It tells you whether "regulatory
evidence" is a real category for them or a story, and it costs one sentence.

If they say "we would need to know what those endpoints return" — that is the
inline pilot selling itself, and the second conversation has begun.
