import { Reveal, GhostButton, TextLink } from '../lib/ui.jsx'
import SignalLine from './SignalLine.jsx'

export default function Hero() {
  return (
    <section className="relative flex flex-col items-center px-6 pb-4 pt-16 text-center md:pt-24">
      <Reveal>
        <h1 className="mx-auto max-w-3xl text-balance font-serif text-[clamp(34px,6vw,64px)] font-normal leading-[1.12] tracking-[-0.025em] text-ink">
          API security that runs inside your network, not ours.
        </h1>
      </Reveal>
      <Reveal delay={0.08}>
        <p className="mx-auto mt-6 max-w-2xl text-[17px] leading-relaxed text-muted">
          AEGIS maps every endpoint from live traffic, stops the attacks a signature
          firewall cannot see, and produces the evidence NIS2 and DORA ask for.
          One Go binary on your hardware, against your database. No traffic leaves
          your infrastructure.
        </p>
      </Reveal>
      <Reveal delay={0.16}>
        <div className="mt-8 flex flex-col items-center gap-4 sm:flex-row sm:justify-center">
          <GhostButton href="#pilot">Start with a mirror pilot</GhostButton>
          <TextLink href="/how-it-works.html">How it works, end to end</TextLink>
        </div>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="mx-auto mt-6 max-w-xl text-[13.5px] leading-relaxed text-faint">
          A pilot does not put us in your request path. Your proxy mirrors a copy;
          we never touch the response. Stop the gateway mid-pilot and your traffic
          does not notice.
        </p>
      </Reveal>
      <Reveal delay={0.26} className="mt-14 w-full md:mt-20">
        <SignalLine />
      </Reveal>
    </section>
  )
}
