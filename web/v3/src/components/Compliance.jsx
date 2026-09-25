import { Reveal, SectionHeader, Badge, TextLink } from '../lib/ui.jsx'
import { useT } from '../lib/i18n.jsx'

export default function Compliance() {
  const t = useT()
  return (
    <section id="compliance" className="border-t border-line py-16 md:py-20">
      <Reveal>
        <SectionHeader title={t.compliance.title} sub={t.compliance.sub} />
      </Reveal>
      <div className="mt-10 divide-y divide-line border-t border-line">
        {t.compliance.frameworks.map(([tag, name, body], i) => (
          <Reveal key={tag} delay={i * 0.06}>
            <div className="grid grid-cols-1 gap-3 py-7 sm:grid-cols-[150px_1fr] sm:gap-8">
              <div><Badge tone="accent">{tag}</Badge></div>
              <div>
                <h3 className="text-[16px] font-medium text-ink">{name}</h3>
                <p className="mt-2 max-w-2xl text-[14.5px] leading-relaxed text-muted">{body}</p>
              </div>
            </div>
          </Reveal>
        ))}
      </div>

      {/* Stated unprompted, because an auditor asks it anyway — and the
          difference between "they told me" and "I found out" is the difference
          between a partner and a vendor. */}
      <Reveal delay={0.24}>
        <div className="mt-10 max-w-2xl rounded-2xl border border-line-2 bg-card p-6">
          <h3 className="text-[15px] font-medium text-ink">{t.compliance.limitsTitle}</h3>
          <p className="mt-2 text-[14px] leading-relaxed text-muted">{t.compliance.limits1}</p>
          <p className="mt-3 text-[14px] leading-relaxed text-muted">{t.compliance.limits2}</p>
          <div className="mt-4">
            <TextLink href="/articles.html">{t.compliance.limitsLink}{t.englishOnly}</TextLink>
          </div>
        </div>
      </Reveal>
    </section>
  )
}
