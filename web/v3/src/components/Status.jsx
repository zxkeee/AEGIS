import { Reveal, SectionHeader, Badge, TextLink } from '../lib/ui.jsx'

const DONE = [
  ['The full control chain', 'WAF, DLP, JWT identity, BOLA detection, passive discovery, multi-tenancy.'],
  ['Schema enforcement', 'Rejects undocumented body fields against your OpenAPI contract — closes mass assignment.'],
  ['Adversarial testing', 'WAF-evasion fuzzing and dynamic scans against a running instance.'],
  ['Fails safe by design', 'Every control has a documented fail-open or fail-closed choice.'],
]
const OPEN = [
  ['An external pentest', 'An independent audit before any production claim.'],
  ['Deeper attack detection', 'Injection patterns, auth-velocity anomalies.'],
  ['Real deployments', 'On live traffic, which is where a design partner comes in.'],
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
          sub="A working gateway with real controls, tested by our own adversarial work. What it is not yet, it says so."
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
