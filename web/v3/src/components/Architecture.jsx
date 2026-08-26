import { Reveal, SectionHeader } from '../lib/ui.jsx'

const ROWS = [
  ['01', 'Resolve', 'TenantResolve, CleanHeaders, LicenseRateLimit'],
  ['02', 'Fingerprint', 'UpstreamFingerprint, TLSFingerprint'],
  ['03', 'Harden', 'SecurityHeaders, RequestID, PathSanity, CORS'],
  ['04', 'Filter', 'IPGuard, ThreatFeed, RateLimit, BotProtection, Challenge'],
  ['05', 'Inspect', 'WAF (OWASP CRS + XXE screen)'],
  ['06', 'Discover', 'Discovery, passive catalog'],
  ['07', 'Authorize', 'Auth (JWT), SchemaValidation'],
  ['08', 'Detect and redact', 'AbuseDetection, DLP, BehaviorAnalysis'],
]

export default function Architecture() {
  return (
    <section id="how" className="border-t border-line py-16 md:py-20">
      <Reveal>
        <SectionHeader
          title="The order is load-bearing."
          sub="Identity resolves before anything else runs. Forged headers are stripped before a control could trust them. Every request walks the same eight-stage chain, in this order, before it reaches your backend."
        />
      </Reveal>
      <Reveal delay={0.08}>
        <div className="mt-10 overflow-x-auto">
          <table className="w-full min-w-[560px] border-collapse text-left">
            <thead>
              <tr className="border-b border-line-2 text-[11px] font-medium uppercase tracking-[0.05em] text-muted">
                <th className="w-12 py-3 pr-4 font-medium">No.</th>
                <th className="py-3 pr-4 font-medium">Stage</th>
                <th className="py-3 font-medium">Middleware</th>
              </tr>
            </thead>
            <tbody className="font-mono text-[13px]">
              {ROWS.map(([n, stage, detail], i) => (
                <tr key={n} className={`border-b border-line ${i % 2 === 1 ? 'bg-elevated/40' : ''}`}>
                  <td className="py-3.5 pr-4 text-faint">{n}</td>
                  <td className="py-3.5 pr-4 font-sans font-medium text-ink">{stage}</td>
                  <td className="py-3.5 text-muted">{detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Reveal>
    </section>
  )
}
