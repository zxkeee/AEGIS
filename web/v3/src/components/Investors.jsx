import { Reveal, SectionHeader, TextLink } from '../lib/ui.jsx'
import { useT } from '../lib/i18n.jsx'

/* The investor section exists because the rest of the page answers "should I
   buy this" and an investor is asking a different question. What it does NOT
   contain is a market size: nobody here measured one, and an unsourced TAM is
   the first number a fund checks and the fastest way to lose the rest of the
   page with it. */

export default function Investors() {
  const t = useT()
  return (
    <section id="investors" className="border-t border-line py-16 md:py-20 scroll-mt-16">
      <Reveal>
        <SectionHeader title={t.investors.title} sub={t.investors.sub} />
      </Reveal>
      <div className="mt-10 grid gap-x-12 gap-y-9 md:grid-cols-2">
        {t.investors.blocks.map(([title, body], i) => (
          <Reveal key={title} delay={i * 0.06}>
            <div className="border-t border-line pt-6">
              <div className="font-mono text-[11px] tracking-[0.08em] text-faint">
                {String(i + 1).padStart(2, '0')}
              </div>
              <h3 className="mt-2 font-serif text-[22px] leading-snug text-ink">{title}</h3>
              <p className="mt-3 text-[14.5px] leading-relaxed text-muted">{body}</p>
            </div>
          </Reveal>
        ))}
      </div>
      <Reveal delay={0.2}>
        <p className="mt-10 max-w-2xl text-[14px] leading-relaxed text-faint">{t.investors.note}</p>
        <div className="mt-4">
          <TextLink href={t.paths.howItWorks}>{t.investors.link}</TextLink>
        </div>
      </Reveal>
    </section>
  )
}
