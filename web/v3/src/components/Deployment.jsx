import { Reveal, SectionHeader, Badge } from '../lib/ui.jsx'

/* The section the site was missing entirely. Every capability AEGIS ships
   exists somewhere in the market, usually more mature. The part an incumbent
   cannot copy is WHERE IT RUNS — so that belongs on the page, not only in the
   sales deck. */

const MODES = [
  [
    'Mirror',
    'Zero risk. How a pilot starts.',
    'Your proxy sends a copy of each request. AEGIS never sits in the request path and never touches the response. You can stop the gateway in the middle of a pilot and nothing changes for your users — which is the objection that ends most first conversations, removed rather than argued with.',
  ],
  [
    'Observe',
    'Inline, blocking nothing.',
    'The full chain runs on real traffic: every endpoint catalogued, every finding raised, every response classified — and nothing denied, nothing redacted. The step between reading a report and trusting an enforcement decision.',
  ],
  [
    'Enforce',
    'The whole chain, deciding.',
    'WAF, rate limits, IP and bot controls, BOLA and BFLA blocking, response redaction. Each control carries its own documented fail-open or fail-closed choice, so an outage in Redis is a decision you made in advance rather than one the gateway makes for you.',
  ],
]

export default function Deployment() {
  return (
    <section id="deployment" className="border-t border-line py-16 md:py-20 scroll-mt-16">
      <Reveal>
        <SectionHeader
          title="Self-hosted is not a deployment option. It is the product."
          sub="Salt, Noname, Imperva and Akamai's API security are SaaS: they need a copy of your traffic inside their cloud. For a DORA-regulated bank, a hospital or a public-sector body, that is not a preference — it is a bar they cannot clear. AEGIS is one Go binary. No agents, no sidecars, no tenancy in somebody else's account, no traffic leaving your network. Data residency is the default, not an enterprise add-on."
        />
      </Reveal>
      <div className="mt-10 divide-y divide-line border-t border-line">
        {MODES.map(([tag, lead, body], i) => (
          <Reveal key={tag} delay={i * 0.06}>
            <div className="grid grid-cols-1 gap-3 py-7 sm:grid-cols-[140px_1fr] sm:gap-8">
              <div><Badge tone="accent">{tag}</Badge></div>
              <div>
                <h3 className="text-[16px] font-medium text-ink">{lead}</h3>
                <p className="mt-2 max-w-2xl text-[14.5px] leading-relaxed text-muted">{body}</p>
              </div>
            </div>
          </Reveal>
        ))}
      </div>
      <Reveal delay={0.2}>
        <p className="mt-8 max-w-2xl text-[14px] leading-relaxed text-faint">
          All three are the same binary and the same configuration file. Moving from
          mirror to enforcement is a setting, not a migration.
        </p>
      </Reveal>
    </section>
  )
}
