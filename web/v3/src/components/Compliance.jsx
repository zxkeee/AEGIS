import { Reveal, SectionHeader, Badge, TextLink } from '../lib/ui.jsx'

const FRAMEWORKS = [
  [
    'NIS2',
    'Network and Information Security Directive, Art. 21 and 23',
    'Exposed endpoints, missing authentication and data-exposure findings map to the risk-management obligations. Correlated incidents carry the Art. 23 reporting deadlines — the 24-hour early warning and the 72-hour notification — and closing an incident does not erase a deadline that was missed.',
  ],
  [
    'DORA',
    'Digital Operational Resilience Act, Art. 8-10 and 17-19',
    'The ICT risk-management articles map to discovery and posture; the incident articles map to the register, which separates what the gateway observed from what an operator asserted. Written for financial entities in the EU, where a SaaS security layer holding a copy of the traffic is the harder question.',
  ],
  [
    'ISO 27001',
    'Information Security Management, Annex A',
    'Discovery, posture scoring and the admin action trail line up with the Annex A controls for access, logging and secure operations.',
  ],
]

export default function Compliance() {
  return (
    <section id="compliance" className="border-t border-line py-16 md:py-20">
      <Reveal>
        <SectionHeader
          title="The same signal that protects your APIs feeds the paperwork."
          sub="Every finding ties to a control a European audit checks against, through the OWASP API Top 10. A signed report is Ed25519 on a key held separately from every other secret, and your auditor checks it on their own machine with reportverify — a standalone binary that refuses to run against a key taken from the document it is checking, so verifying costs them no trust in you or in us."
        />
      </Reveal>
      <div className="mt-10 divide-y divide-line border-t border-line">
        {FRAMEWORKS.map(([tag, name, body], i) => (
          <Reveal key={tag} delay={i * 0.06}>
            <div className="grid grid-cols-1 gap-3 py-7 sm:grid-cols-[140px_1fr] sm:gap-8">
              <div><Badge tone="accent">{tag}</Badge></div>
              <div>
                <h3 className="text-[16px] font-medium text-ink">{name}</h3>
                <p className="mt-2 max-w-2xl text-[14.5px] leading-relaxed text-muted">{body}</p>
              </div>
            </div>
          </Reveal>
        ))}
      </div>

      {/* Said here, unprompted, because an auditor asks it anyway — and the
          difference between "they told me" and "I found out" is the difference
          between a partner and a vendor. */}
      <Reveal delay={0.24}>
        <div className="mt-10 max-w-2xl rounded-2xl border border-line-2 bg-card p-6">
          <h3 className="text-[15px] font-medium text-ink">What a signature does not prove</h3>
          <p className="mt-2 text-[14px] leading-relaxed text-muted">
            The forensic log is sealed hourly with Merkle roots in a signed chain;
            the incident register and the admin action trail are chained and signed
            too. Deleting a row, editing one or removing a tail is detectable —
            including when the operator does it.
          </p>
          <p className="mt-3 text-[14px] leading-relaxed text-muted">
            The correct word is tamper-<em>evident</em>, never tamper-proof. The
            signing key is held by the party being audited, so a signature proves a
            document was not altered after it was produced — not that it was
            assembled from complete data. An external anchor, a timestamp authority
            or a transparency log, would close that; it is not built. Every signed
            document states this inside itself, and the system refuses to sign one
            that carries no limits section.
          </p>
          <div className="mt-4">
            <TextLink href="/articles.html">How the chains are built</TextLink>
          </div>
        </div>
      </Reveal>
    </section>
  )
}
