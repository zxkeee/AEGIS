import { ShieldCheck, EyeSlash, Fingerprint, UserFocus, MapTrifold, Buildings } from '@phosphor-icons/react'
import { Reveal, SectionHeader } from '../lib/ui.jsx'

const TILES = [
  [ShieldCheck, 'Web app firewall', 'OWASP CRS + XXE screen'],
  [EyeSlash, 'Data masking', 'Cards, IDs, emails redacted'],
  [Fingerprint, 'Signed identity', 'JWT verified, forwarded signed'],
  [UserFocus, 'BOLA / BFLA', 'Cross-owner access, REST + GraphQL'],
  [MapTrifold, 'Passive discovery', 'Live endpoint catalog'],
  [Buildings, 'Multi-tenant isolation', 'Cache and database scoped'],
]

export default function WorkflowGrid() {
  return (
    <section id="controls" className="border-t border-line py-16 md:py-20">
      <Reveal>
        <SectionHeader title="Six controls, one ordered chain." align="center" />
      </Reveal>
      <div className="mx-auto mt-12 grid max-w-5xl grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-6">
        {TILES.map(([Icon, title, note], i) => (
          <Reveal key={title} delay={i * 0.04}>
            <div className="group flex h-full flex-col items-center rounded-lg bg-paper p-6 text-center transition-all duration-300 hover:-translate-y-1 hover:shadow-[0_10px_28px_rgba(0,0,0,0.35)]">
              <Icon
                size={26}
                weight="light"
                className="text-navy transition-all duration-300 group-hover:scale-110 group-hover:text-accent"
              />
              <div className="mt-4 text-[13px] font-medium text-obsidian">{title}</div>
              <div className="mt-1.5 text-[11.5px] leading-snug text-[#57544d]">{note}</div>
            </div>
          </Reveal>
        ))}
      </div>
    </section>
  )
}
