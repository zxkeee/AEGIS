import { Reveal, SectionHeader, Badge, TextLink } from '../lib/ui.jsx'
import { useT } from '../lib/i18n.jsx'

function List({ items, label }) {
  return (
    <div className="divide-y divide-line border-t border-line">
      {items.map(([title, body]) => (
        <div key={title} className="flex flex-col gap-2 py-5 sm:flex-row sm:items-baseline sm:gap-6">
          <div className="flex-none sm:w-24"><Badge>{label}</Badge></div>
          <div>
            <span className="text-[15px] font-medium text-ink">{title}.</span>{' '}
            <span className="text-[14.5px] text-muted">{body}</span>
          </div>
        </div>
      ))}
    </div>
  )
}

export default function Status() {
  const t = useT()
  return (
    <section id="status" className="border-t border-line py-16 md:py-20">
      <Reveal>
        <SectionHeader title={t.status.title} sub={t.status.sub} />
      </Reveal>
      <Reveal delay={0.08}>
        <div className="mt-10 grid gap-10 md:grid-cols-2 md:gap-14">
          <List label={t.status.shipped} items={t.status.done} />
          <List label={t.status.open} items={t.status.todo} />
        </div>
      </Reveal>
      <Reveal delay={0.14}>
        <div className="mt-10">
          <TextLink href="/articles.html">{t.status.link}{t.englishOnly}</TextLink>
        </div>
      </Reveal>
    </section>
  )
}
