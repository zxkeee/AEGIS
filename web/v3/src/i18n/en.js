/* The site's source of truth for copy. Polish and Ukrainian mirror this shape;
   a key missing there falls back to the English string rather than rendering a
   hole. Middleware names are identifiers and stay untranslated in every
   language — an operator greps for "BehaviorProfile", not for its Polish. */

export default {
  nav: {
    items: [
      ['Architecture', '#how'],
      ['Controls', '#controls'],
      ['Deployment', '#deployment'],
      ['Compliance', '#compliance'],
      ['Investors', '#investors'],
      ['Status', '#status'],
    ],
    cta: 'Start a mirror pilot',
    skip: 'Skip to content',
  },

  hero: {
    title: 'API security that runs inside your network, not ours.',
    sub: 'AEGIS maps every endpoint from live traffic, stops the attacks a signature firewall cannot see, and produces the evidence NIS2 and DORA ask for. One Go binary on your hardware, against your database. No traffic leaves your infrastructure.',
    cta: 'Start with a mirror pilot',
    link: 'How it works, end to end',
    note: 'A pilot does not put us in your request path. Your proxy mirrors a copy; we never touch the response. Stop the gateway mid-pilot and your traffic does not notice.',
  },

  terminal: {
    title: 'A record of every request, not a quarterly scan.',
    sub: 'AEGIS reads production traffic as it happens — from a mirrored copy during a pilot, inline once you choose to enforce. Every block, redaction and newly seen endpoint lands in a forensic log the moment it occurs, sealed hourly so the log can prove it was not edited afterwards.',
    link: 'See how the chain decides',
  },

  controls: {
    title: 'Six controls, one ordered chain.',
    tiles: [
      ['Web app firewall', 'OWASP CRS v4 + XXE screen'],
      ['Data masking', 'Cards, IDs, emails redacted'],
      ['Signed identity', 'JWT verified, forwarded signed'],
      ['BOLA / BFLA', 'Cross-owner access, REST + GraphQL'],
      ['Passive discovery', 'Live endpoint catalog'],
      ['Multi-tenant isolation', 'Cache and database scoped'],
    ],
  },

  architecture: {
    title: 'The order is load-bearing.',
    sub: 'Identity resolves before anything else runs. Forged headers are stripped before a control could trust them. The firewall runs before discovery, so a blocked attack never enters your catalog. Twenty-three middleware in eight stages, in this order, before a request reaches your backend.',
    head: ['No.', 'Stage', 'Middleware', 'Steps'],
    stages: ['Resolve', 'Fingerprint', 'Harden', 'Filter', 'Inspect', 'Discover', 'Authorize', 'Detect and redact'],
    note: 'The order is not documentation. It is pinned by a test that states the consequence of breaking each rule, because prose drifts and a test does not — this page said the chain had eight steps until somebody counted.',
  },

  deployment: {
    title: 'Self-hosted is not a deployment option. It is the product.',
    sub: 'Salt, Noname, Imperva and Akamai’s API security are SaaS: they need a copy of your traffic inside their cloud. For a DORA-regulated bank, a hospital or a public-sector body, that is not a preference — it is a bar they cannot clear. AEGIS is one Go binary. No agents, no sidecars, no tenancy in somebody else’s account, no traffic leaving your network. Data residency is the default, not an enterprise add-on.',
    modes: [
      ['Mirror', 'Zero risk. How a pilot starts.', 'Your proxy sends a copy of each request. AEGIS never sits in the request path and never touches the response. You can stop the gateway in the middle of a pilot and nothing changes for your users — which is the objection that ends most first conversations, removed rather than argued with.'],
      ['Observe', 'Inline, blocking nothing.', 'The full chain runs on real traffic: every endpoint catalogued, every finding raised, every response classified — and nothing denied, nothing redacted. The step between reading a report and trusting an enforcement decision.'],
      ['Enforce', 'The whole chain, deciding.', 'WAF, rate limits, IP and bot controls, BOLA and BFLA blocking, response redaction. Each control carries its own documented fail-open or fail-closed choice, so an outage in Redis is a decision you made in advance rather than one the gateway makes for you.'],
    ],
    note: 'All three are the same binary and the same configuration file. Moving from mirror to enforcement is a setting, not a migration.',
  },

  compliance: {
    title: 'The same signal that protects your APIs feeds the paperwork.',
    sub: 'Every finding ties to a control a European audit checks against, through the OWASP API Top 10. A signed report is Ed25519 on a key held separately from every other secret, and your auditor checks it on their own machine with reportverify — a standalone binary that refuses to run against a key taken from the document it is checking, so verifying costs them no trust in you or in us.',
    frameworks: [
      ['NIS2', 'Network and Information Security Directive, Art. 21 and 23', 'Exposed endpoints, missing authentication and data-exposure findings map to the risk-management obligations. Correlated incidents carry the Art. 23 reporting deadlines — the 24-hour early warning and the 72-hour notification — and closing an incident does not erase a deadline that was missed.'],
      ['DORA', 'Digital Operational Resilience Act, Art. 8–10 and 17–19', 'The ICT risk-management articles map to discovery and posture; the incident articles map to the register, which separates what the gateway observed from what an operator asserted. Written for financial entities in the EU, where a SaaS security layer holding a copy of the traffic is the harder question.'],
      ['ISO 27001', 'Information Security Management, Annex A', 'Discovery, posture scoring and the admin action trail line up with the Annex A controls for access, logging and secure operations.'],
    ],
    limitsTitle: 'What a signature does not prove',
    limits1: 'The forensic log is sealed hourly with Merkle roots in a signed chain; the incident register and the admin action trail are chained and signed too. Deleting a row, editing one or removing a tail is detectable — including when the operator does it.',
    limits2: 'The correct word is tamper-evident, never tamper-proof. The signing key is held by the party being audited, so a signature proves a document was not altered after it was produced — not that it was assembled from complete data. An external anchor, a timestamp authority or a transparency log, would close that; it is not built. Every signed document states this inside itself, and the system refuses to sign one that carries no limits section.',
    limitsLink: 'How the chains are built',
  },

  investors: {
    title: 'Why this, and why now.',
    sub: 'Every figure here is one we can show you the source for. Market sizing is not on this page: we did not measure it, and a number we did not measure is the first thing you would check.',
    blocks: [
      [
        'The deadlines have already passed',
        'NIS2 had to be in national law across the EU by 17 October 2024. DORA has applied to EU financial entities since 17 January 2025. These are obligations with dates attached, not intentions — which is why a buyer in this category takes the meeting this year instead of next.',
      ],
      [
        'Where it runs is the whole wedge',
        'Every capability here exists somewhere in the market, usually more mature. The part an incumbent cannot copy is the deployment model: a SaaS company built on its own cloud will not sell a binary that runs in the customer’s datacentre, because that binary competes with its margin. Technically nothing stops them. Their own business model does.',
      ],
      [
        'What is built, and how we know',
        '27,700 lines of Go product code against 28,200 lines of tests — more test code than product code. Per-package coverage floors from 70% to 100%, enforced in CI. Eleven security invariants encoded as scripts, each one a bug that shipped once and cannot ship again. Mutation testing as a working practice rather than a slogan: the code is deliberately broken to prove the tests notice, and that has caught eleven tests that were green on broken code — all eleven listed individually, which is why the number is not rounder.',
      ],
      [
        'What is not built, stated first',
        'No customer. No revenue. No independent penetration test — the scope document is written, it is not commissioned. No SOC 2 and no ISO certificate, because those are a process and an auditor rather than a feature. One engineer on the technical side. Technology readiness sits at TRL 5, arguably 6: the system runs and is verified end to end in our own environment, and TRL 7 needs one deployment on somebody else’s real traffic. That is a single pilot, not a year of work.',
      ],
    ],
    note: 'The long version is linked below: an architecture write-up and the engineering articles. Nothing in them contradicts the code — a check in CI fails the build when a document and the code disagree, which is how the two errors named on this page were found.',
    link: 'Read the architecture write-up',
  },

  status: {
    title: 'Early, and straight about it.',
    sub: 'A working gateway with real controls and more test code than product code. What it is not yet, it says here rather than letting you find out later — the second one costs more.',
    shipped: 'Shipped',
    open: 'Open',
    done: [
      ['The full control chain', 'Twenty-three middleware: WAF, DLP, signed JWT identity, BOLA and BFLA, passive discovery, multi-tenant isolation.'],
      ['Per-consumer baselines', 'Volume, authorisation failures, missing paths and endpoint spread — each finding names the dimension and the size of the deviation.'],
      ['GraphQL coverage', 'BOLA, discovery and PII detection cover GraphQL operations, not just REST paths.'],
      ['Schema enforcement', 'Rejects undocumented body fields against your OpenAPI contract — closes mass assignment.'],
      ['Tamper-evident evidence', 'Hourly Merkle seals on the forensic log, signed heads on the incident register and the admin action trail.'],
      ['Fails safe by design', 'Every control carries a documented fail-open or fail-closed choice, and the default is written down with its reason.'],
    ],
    todo: [
      ['No paying customers', 'No pilot has run on somebody else’s traffic yet. You would be the first, which is exactly why a pilot starts in mirror mode.'],
      ['No external pentest', 'The scope document is written; it is not commissioned. What exists is internal adversarial work and the discipline that found it.'],
      ['No external anchor', 'Signed evidence lives in your database and the key is yours, so an operator holding it could rewrite a record and re-sign. A timestamp authority closes this; it is not built.'],
      ['No certification', 'No SOC 2, no ISO certificate. Those are a process and an auditor, not a feature — what we can hand over today is the technical evidence that would go into one.'],
    ],
    link: 'Read our engineering writing',
  },

  pilot: {
    title: 'Run AEGIS on a copy of your traffic for a week.',
    sub: 'Your proxy mirrors each request to us. We are not in the path, we never touch a response, and stopping the gateway mid-pilot changes nothing for your users. At the end you get a findings report: the shadow APIs, the endpoints leaking data, and who is calling them.',
    bullets: [
      'One week, mirror mode, no cost',
      'Nothing in your request path, nothing to roll back',
      'Findings mapped to NIS2, DORA and ISO 27001',
      'Runs on your hardware — no traffic leaves your network',
    ],
    form: {
      name: 'Name',
      email: 'Work email',
      company: 'Company',
      interest: 'I am interested in',
      select: 'Select...',
      options: ['Running a pilot', 'An enterprise demo', 'Investing or partnering'],
      message: 'Anything we should know?',
      optional: 'optional',
      submit: 'Start a mirror pilot',
      sending: 'Sending...',
      thanks: 'Thank you, we will be in touch within a day.',
      mail: 'Opening your email client...',
    },
  },

  footer: {
    blurb: 'Self-hosted API security gateway, built in Go. Your hardware, your database, no traffic leaving your network. Seeking design partners.',
  },

  englishOnly: '',
}
