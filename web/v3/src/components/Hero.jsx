import { Reveal, GhostButton, TextLink } from '../lib/ui.jsx'
import { useT } from '../lib/i18n.jsx'
import SignalLine from './SignalLine.jsx'

export default function Hero() {
  const t = useT()
  return (
    <section className="relative flex flex-col items-center px-6 pb-4 pt-16 text-center md:pt-24">
      <Reveal>
        <h1 className="mx-auto max-w-3xl text-balance font-serif text-[clamp(34px,6vw,64px)] font-normal leading-[1.12] tracking-[-0.025em] text-ink">
          {t.hero.title}
        </h1>
      </Reveal>
      <Reveal delay={0.08}>
        <p className="mx-auto mt-6 max-w-2xl text-[17px] leading-relaxed text-muted">{t.hero.sub}</p>
      </Reveal>
      <Reveal delay={0.16}>
        <div className="mt-8 flex flex-col items-center gap-4 sm:flex-row sm:justify-center">
          <GhostButton href="#pilot">{t.hero.cta}</GhostButton>
          <TextLink href="/how-it-works.html">{t.hero.link}{t.englishOnly}</TextLink>
        </div>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="mx-auto mt-6 max-w-xl text-[13.5px] leading-relaxed text-faint">{t.hero.note}</p>
      </Reveal>
      <Reveal delay={0.26} className="mt-14 w-full md:mt-20">
        <SignalLine />
      </Reveal>
    </section>
  )
}
