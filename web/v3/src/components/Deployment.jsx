import { Reveal, SectionHeader, Badge } from '../lib/ui.jsx'
import { useT } from '../lib/i18n.jsx'

/* Every capability AEGIS ships exists somewhere in the market, usually more
   mature. The part an incumbent cannot copy is WHERE IT RUNS, so it belongs on
   the page rather than only in a sales deck. */

export default function Deployment() {
  const t = useT()
  return (
    <section id="deployment" className="border-t border-line py-16 md:py-20 scroll-mt-16">
      <Reveal>
        <SectionHeader title={t.deployment.title} sub={t.deployment.sub} />
      </Reveal>
      <div className="mt-10 divide-y divide-line border-t border-line">
        {t.deployment.modes.map(([tag, lead, body], i) => (
          <Reveal key={tag} delay={i * 0.06}>
            <div className="grid grid-cols-1 gap-3 py-7 sm:grid-cols-[150px_1fr] sm:gap-8">
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
        <p className="mt-8 max-w-2xl text-[14px] leading-relaxed text-faint">{t.deployment.note}</p>
      </Reveal>
    </section>
  )
}
