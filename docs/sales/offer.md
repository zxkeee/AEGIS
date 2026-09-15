# The first offer

What is being sold, to whom, for how much, and what is deliberately not
promised. Everything else in this directory inherits its wording from here — and
this file inherits its positioning from [`docs/PRODUCT.md`](../PRODUCT.md), which
is where a change to what the product *is* goes first.

The offer below sells **stage one of three** (See). Protect is the second
conversation and Prove the third; PRODUCT.md §3 explains why that order is not
negotiable.

## The offer

> **A map of your API surface.** What is actually exposed, who calls it, and
> what is not in your documentation. Three weeks. **We do not touch your
> traffic** — AEGIS runs on a mirror, and you can switch it off mid-pilot to
> prove it.

**Price: free for the first three, €3 000 after.**

Free is not generosity, it is a trade: a written reference and permission to
name them. The fourth conversation is priced, because ten companies accepting
something free tells you nothing about whether anyone will pay for it.

## Why the mirror leads

The objection that ends a first pilot is *"I am not putting your process in
front of my traffic"*, and it is a fair one. Answer it before it is raised:

> Your nginx sends a **copy** of each request to us and throws away the reply.
> Your traffic never passes through our process. Stop us mid-pilot and watch
> your dashboards — nothing changes. That is the point.

The demonstration costs them nothing and it is the single most persuasive thing
available. Ask for it explicitly; do not wait to be asked.

## What the pilot produces

- Every endpoint actually being called, with `/users/42` and `/users/99`
  collapsed into `/users/{id}`.
- Which of those are **not** in their OpenAPI spec, if they have one.
- Who calls what — per consumer, by JWT subject or API key, not by IP.
- Which endpoints are reached with no authentication at all.
- A signed report, verifiable with a standalone binary they keep.

## What the pilot does NOT produce, and say so first

Mirror mode carries no response, so:

- **No PII findings.** "This endpoint returns card numbers to anonymous
  callers" requires the response body.
- **No object-ownership (BOLA) findings.** Same reason.
- **No status codes or latency.**

Those need an inline pilot, and that is the **second** conversation — after
they have seen the map and decided you are worth a hop in their path.

Saying this first costs one sentence and buys the only thing that matters at
this stage: they believe the rest.

## Who to approach

| Segment | Why now |
|---|---|
| Polish / Baltic fintech, payments, neobanks, 50–500 staff | DORA has applied since 17 Jan 2025; the deadline is behind them |
| Ukrainian product companies with EU customers | Security questionnaires arrive from those customers and there is nothing to answer with |
| Any SaaS that recently received an audit or a questionnaire | They have the pain **this month**, not in the abstract |
| People you already know with a working API | First pilot goes to whoever forgives the missing legal entity |

The last row is first in order. One acquaintance beats forty cold emails, and
the paperwork problem below does not exist there.

## The paperwork problem

Without a legal entity you cannot sign a DPA, and a regulated company will not
let an unincorporated individual near traffic containing personal data. That is
not pedantry — it makes you an undeclared processor under GDPR while selling
compliance.

Two consequences:

1. Start with companies that will overlook it — people who know you.
2. `mirror_request_body off` in their nginx means AEGIS sees **paths, methods
   and headers, not bodies**. Far less personal data crosses the boundary,
   which makes the conversation with their lawyer shorter. Offer it by default.

Incorporate after the first "yes", not before. Spending €1 150 on a Sp. z o.o.
to discover nobody wants the thing is the wrong order.

## Four weeks

| Week | Target |
|---|---|
| 1 | 40-company list. This offer written as a one-pager. Emails to everyone you know — **today** |
| 2 | 40 emails sent. Target: 10 replies |
| 3 | Calls and demos. Target: 3 agreements |
| 4 | First mirror running against real traffic |

Zero pilots running at the end of week four falsifies the thesis. That is a
result, not a failure — and it cost four weeks instead of another year.
