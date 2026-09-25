import { Reveal, SectionHeader } from '../lib/ui.jsx'
import { useT } from '../lib/i18n.jsx'

/* Twenty-three middleware in eight stages. The middleware column is the same
   in every language: these are identifiers an operator greps for, and the
   counts are there because the previous version of this table said "eight
   stages" while silently dropping ConsumerID and BehaviorProfile. */
const ROWS = [
  ['TenantResolve, CleanHeaders, LicenseRateLimit', 3],
  ['UpstreamFingerprint, TLSFingerprint', 2],
  ['SecurityHeaders, RequestID, PathSanity, CORS', 4],
  ['IPGuard, ThreatFeed, RateLimit, BotProtection, Challenge', 5],
  ['WAF (OWASP CRS v4 via Coraza, plus an XXE screen)', 1],
  ['Discovery, the passive catalog', 1],
  ['Auth (JWT), ConsumerID, SchemaValidation', 3],
  ['AbuseDetection, DLP, BehaviorAnalysis, BehaviorProfile', 4],
]

export default function Architecture() {
  const t = useT()
  return (
    <section id="how" className="border-t border-line py-16 md:py-20">
      <Reveal>
        <SectionHeader title={t.architecture.title} sub={t.architecture.sub} />
      </Reveal>
      <Reveal delay={0.08}>
        <div className="mt-10 overflow-x-auto">
          <table className="w-full min-w-[620px] border-collapse text-left">
            <thead>
              <tr className="border-b border-line-2 text-[11px] font-medium uppercase tracking-[0.05em] text-muted">
                <th className="w-12 py-3 pr-4 font-medium">{t.architecture.head[0]}</th>
                <th className="py-3 pr-4 font-medium">{t.architecture.head[1]}</th>
                <th className="py-3 pr-4 font-medium">{t.architecture.head[2]}</th>
                <th className="w-14 py-3 text-right font-medium">{t.architecture.head[3]}</th>
              </tr>
            </thead>
            <tbody className="font-mono text-[13px]">
              {ROWS.map(([detail, count], i) => (
                <tr key={detail} className={`border-b border-line ${i % 2 === 1 ? 'bg-elevated/40' : ''}`}>
                  <td className="py-3.5 pr-4 text-faint">{String(i + 1).padStart(2, '0')}</td>
                  <td className="py-3.5 pr-4 font-sans font-medium text-ink">{t.architecture.stages[i]}</td>
                  <td className="py-3.5 pr-4 text-muted">{detail}</td>
                  <td className="py-3.5 text-right text-faint">{count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Reveal>
      <Reveal delay={0.14}>
        <p className="mt-6 max-w-2xl text-[14px] leading-relaxed text-faint">{t.architecture.note}</p>
      </Reveal>
    </section>
  )
}
