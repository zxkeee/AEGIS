import { ShieldCheck, EyeSlash, Fingerprint, UserFocus, MapTrifold, Buildings } from '@phosphor-icons/react'
import { Reveal, SectionHeader } from '../lib/ui.jsx'
import { useT } from '../lib/i18n.jsx'

const ICONS = [ShieldCheck, EyeSlash, Fingerprint, UserFocus, MapTrifold, Buildings]

export default function WorkflowGrid() {
  const t = useT()
  return (
    <section id="controls" className="border-t border-line py-16 md:py-20">
      <Reveal>
        <SectionHeader title={t.controls.title} align="center" />
      </Reveal>
      <div className="mx-auto mt-12 grid max-w-5xl grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-6">
        {t.controls.tiles.map(([title, note], i) => {
          const Icon = ICONS[i]
          return (
            <Reveal key={title} delay={i * 0.04}>
              <div className="group flex h-full flex-col items-center rounded-lg bg-paper p-6 text-center transition-all duration-300 hover:-translate-y-1 hover:shadow-[0_10px_28px_rgba(0,0,0,0.35)]">
                <Icon size={26} weight="light" className="text-navy transition-all duration-300 group-hover:scale-110 group-hover:text-accent" />
                <div className="mt-4 text-[13px] font-medium text-obsidian">{title}</div>
                <div className="mt-1.5 text-[11.5px] leading-snug text-[#57544d]">{note}</div>
              </div>
            </Reveal>
          )
        })}
      </div>
    </section>
  )
}
