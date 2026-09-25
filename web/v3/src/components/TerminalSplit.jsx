import { Reveal, SectionHeader, TextLink } from '../lib/ui.jsx'

const LOG = [
  { t: '09:14:22', tag: 'waf', tone: 'block', line: 'POST /v1/invoices/{id}/export  rule 941100 (XSS)  blocked' },
  { t: '09:14:26', tag: 'bola', tone: 'block', line: 'GET /v1/accounts/8841  subject 8830 is not owner  blocked' },
  { t: '09:14:31', tag: 'dlp', tone: 'warn', line: 'GET /v1/customers/search  2 card numbers redacted in response' },
  { t: '09:14:38', tag: 'discovery', tone: 'info', line: 'POST /internal/v2/refunds  new endpoint, no auth middleware' },
  { t: '09:14:44', tag: 'auth', tone: 'ok', line: 'GET /v1/invoices  JWT verified, identity signed for backend' },
]

const TONE = {
  block: 'text-ink',
  warn: 'text-muted',
  info: 'text-accent',
  ok: 'text-muted',
}

export default function TerminalSplit() {
  return (
    <section className="border-t border-line py-16 md:py-20">
      <div className="grid grid-cols-1 gap-12 md:grid-cols-12 md:gap-10">
        <Reveal className="md:col-span-5">
          <SectionHeader
            title="A record of every request, not a quarterly scan."
            sub="AEGIS reads production traffic as it happens — from a mirrored copy during a pilot, inline once you choose to enforce. Every block, redaction and newly seen endpoint lands in a forensic log the moment it occurs, sealed hourly so the log can prove it was not edited afterwards."
          />
          <div className="mt-6">
            <TextLink href="#how">See how the chain decides</TextLink>
          </div>
        </Reveal>

        <Reveal delay={0.08} className="md:col-span-7">
          <div className="overflow-hidden rounded-2xl border border-line-2 bg-obsidian">
            <div className="flex items-center gap-1.5 border-b border-line px-4 py-3">
              <span className="h-2.5 w-2.5 rounded-full bg-[#ff5f57]" />
              <span className="h-2.5 w-2.5 rounded-full bg-[#febc20]" />
              <span className="h-2.5 w-2.5 rounded-full bg-[#28c840]" />
              <span className="ml-3 text-[12px] text-faint">forensic.log</span>
            </div>
            <div className="overflow-x-auto p-5 font-mono text-[12.5px] leading-[1.9]">
              {LOG.map((row) => (
                <div key={row.t + row.tag} className="flex gap-3 whitespace-nowrap">
                  <span className="text-faint">{row.t}</span>
                  <span className="w-16 flex-none text-muted">{row.tag}</span>
                  <span className={TONE[row.tone]}>{row.line}</span>
                </div>
              ))}
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  )
}
