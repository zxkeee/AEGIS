import { Reveal, GhostButton, TextLink } from '../lib/ui.jsx'
import SignalLine from './SignalLine.jsx'

export default function Hero() {
  return (
    <section className="relative flex flex-col items-center px-6 pb-4 pt-16 text-center md:pt-24">
      <Reveal>
        <h1 className="mx-auto max-w-3xl text-balance font-serif text-[clamp(34px,6vw,64px)] font-normal leading-[1.12] tracking-[-0.025em] text-ink">
          What your APIs expose, before an attacker finds it.
        </h1>
      </Reveal>
      <Reveal delay={0.08}>
        <p className="mx-auto mt-6 max-w-xl text-[17px] leading-relaxed text-muted">
          AEGIS is an inline gateway that inspects every request, maps your endpoints, and matches findings to NIS2 and ISO 27001.
        </p>
      </Reveal>
      <Reveal delay={0.16}>
        <div className="mt-8 flex flex-col items-center gap-4 sm:flex-row sm:justify-center">
          <GhostButton href="#pilot">Request a pilot</GhostButton>
          <TextLink href="/how-it-works.html">How it works, end to end</TextLink>
        </div>
      </Reveal>
      <Reveal delay={0.22} className="mt-14 w-full md:mt-20">
        <SignalLine />
      </Reveal>
    </section>
  )
}
