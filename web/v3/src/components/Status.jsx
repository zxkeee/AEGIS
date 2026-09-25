import { Reveal, SectionHeader, Badge, TextLink } from '../lib/ui.jsx'

const DONE = [
  ['The full control chain', 'Twenty-three middleware: WAF, DLP, signed JWT identity, BOLA and BFLA, passive discovery, multi-tenant isolation.'],
  ['Per-consumer baselines', 'Volume, authorisation failures, missing paths and endpoint spread — each finding names the dimension and the size of the deviation.'],
  ['GraphQL coverage', 'BOLA, discovery and PII detection cover GraphQL operations, not just REST paths.'],
  ['Schema enforcement', 'Rejects undocumented body fields against your OpenAPI contract — closes mass assignment.'],
  ['Tamper-evident evidence', 'Hourly Merkle seals on the forensic log, signed heads on the incident register and the admin action trail.'],
  ['Fails safe by design', 'Every control carries a documented fail-open or fail-closed choice, and the default is written down with its reason.'],
]

const OPEN = [
  ['No paying customers', 'No pilot has run on somebody else’s traffic yet. You would be the first, which is exactly why a pilot starts in mirror mode.'],
  ['No external pentest', 'The scope document is written; it is not commissioned. What exists is internal adversarial work and the discipline that found it.'],
  ['No external anchor', 'Signed evidence lives in your database and the key is yours, so an operator holding it could rewrite a record and re-sign. A timestamp authority closes this; it is not built.'],
  ['No certification', 'No SOC 2, no ISO certificate. Those are a process and an auditor, not a feature — what we can hand over today is the technical evidence that would go into one.'],
]

function List({ items, label }) {
  return (
    <div className="divide-y divide-line border-t border-line">
      {items.map(([title, body]) => (
        <div key={title} className="flex flex-col gap-2 py-5 sm:flex-row sm:items-baseline sm:gap-6">
          <div className="flex-none sm:w-20"><Badge>{label}</Badge></div>
          <div>
            <span className="text-[15px] font-medium text-ink">{title}.</span>{' '}
            <span className="text-[14.5px] text-muted">{body}</span>
          </div>
        </div>
      ))}
    </div>
  )
}

export default function Status() {
  return (
    <section id="status" className="border-t border-line py-16 md:py-20">
      <Reveal>
        <SectionHeader
          title="Early, and straight about it."
          sub="A working gateway with real controls and more test code than product code. What it is not yet, it says here rather than letting you find out later — the second one costs more."
        />
      </Reveal>
      <Reveal delay={0.08}>
        <div className="mt-10 grid gap-10 md:grid-cols-2 md:gap-14">
          <List label="Shipped" items={DONE} />
          <List label="Open" items={OPEN} />
        </div>
      </Reveal>
      <Reveal delay={0.14}>
        <div className="mt-10">
          <TextLink href="/articles.html">Read our engineering writing</TextLink>
        </div>
      </Reveal>
    </section>
  )
}
