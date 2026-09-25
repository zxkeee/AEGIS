import { Reveal, SectionHeader } from '../lib/ui.jsx'

/* Twenty-three middleware in eight stages. The counts are here on purpose:
   the previous version of this table said "eight-stage chain" and silently
   dropped ConsumerID and BehaviorProfile, so a reader who counted found two
   fewer controls than the product has. */

const ROWS = [
  ['01', 'Resolve', 'TenantResolve, CleanHeaders, LicenseRateLimit', 3],
  ['02', 'Fingerprint', 'UpstreamFingerprint, TLSFingerprint', 2],
  ['03', 'Harden', 'SecurityHeaders, RequestID, PathSanity, CORS', 4],
  ['04', 'Filter', 'IPGuard, ThreatFeed, RateLimit, BotProtection, Challenge', 5],
  ['05', 'Inspect', 'WAF (OWASP CRS v4 via Coraza, plus an XXE screen)', 1],
  ['06', 'Discover', 'Discovery, the passive catalog', 1],
  ['07', 'Authorize', 'Auth (JWT), ConsumerID, SchemaValidation', 3],
  ['08', 'Detect and redact', 'AbuseDetection, DLP, BehaviorAnalysis, BehaviorProfile', 4],
]

export default function Architecture() {
  return (
    <section id="how" className="border-t border-line py-16 md:py-20">
      <Reveal>
        <SectionHeader
          title="The order is load-bearing."
          sub="Identity resolves before anything else runs. Forged headers are stripped before a control could trust them. The firewall runs before discovery, so a blocked attack never enters your catalog. Twenty-three middleware in eight stages, in this order, before a request reaches your backend."
        />
      </Reveal>
      <Reveal delay={0.08}>
        <div className="mt-10 overflow-x-auto">
          <table className="w-full min-w-[620px] border-collapse text-left">
            <thead>
              <tr className="border-b border-line-2 text-[11px] font-medium uppercase tracking-[0.05em] text-muted">
                <th className="w-12 py-3 pr-4 font-medium">No.</th>
                <th className="py-3 pr-4 font-medium">Stage</th>
                <th className="py-3 pr-4 font-medium">Middleware</th>
                <th className="w-14 py-3 text-right font-medium">Steps</th>
              </tr>
            </thead>
            <tbody className="font-mono text-[13px]">
              {ROWS.map(([n, stage, detail, count], i) => (
                <tr key={n} className={`border-b border-line ${i % 2 === 1 ? 'bg-elevated/40' : ''}`}>
                  <td className="py-3.5 pr-4 text-faint">{n}</td>
                  <td className="py-3.5 pr-4 font-sans font-medium text-ink">{stage}</td>
                  <td className="py-3.5 pr-4 text-muted">{detail}</td>
                  <td className="py-3.5 text-right text-faint">{count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Reveal>
      <Reveal delay={0.14}>
        <p className="mt-6 max-w-2xl text-[14px] leading-relaxed text-faint">
          The order is not documentation. It is pinned by a test that states the
          consequence of breaking each rule, because prose drifts and a test does
          not — this page said the chain had eight steps until somebody counted.
        </p>
      </Reveal>
    </section>
  )
}
