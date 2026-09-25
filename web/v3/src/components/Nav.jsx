import { useState } from 'react'
import { List, X } from '@phosphor-icons/react'
import { Wordmark, GhostButton } from '../lib/ui.jsx'
import { useT } from '../lib/i18n.jsx'
import LangSwitch from './LangSwitch.jsx'

export default function Nav() {
  const [open, setOpen] = useState(false)
  const t = useT()
  return (
    <header className="relative z-40 border-b border-line">
      <div className="relative flex h-16 w-full items-center justify-between px-6 md:px-10 lg:px-14">
        <a href="#top" className="z-10"><Wordmark /></a>
        <nav className="absolute left-1/2 hidden -translate-x-1/2 items-center gap-7 lg:flex">
          {t.nav.items.map(([label, href]) => (
            <a key={href} href={href} className="text-[14px] text-ink transition-colors hover:text-muted">{label}</a>
          ))}
        </nav>
        <div className="hidden items-center gap-3 md:flex">
          <LangSwitch />
          <GhostButton href="#pilot">{t.nav.cta}</GhostButton>
        </div>
        <div className="flex items-center gap-2 md:hidden">
          <LangSwitch />
          <button className="-mr-2 p-2 text-ink" aria-label="Menu" onClick={() => setOpen((v) => !v)}>
            {open ? <X size={20} /> : <List size={20} />}
          </button>
        </div>
      </div>
      {open && (
        <div className="flex flex-col gap-1 border-t border-line px-6 py-4 md:hidden">
          {[...t.nav.items, [t.nav.cta, '#pilot']].map(([label, href]) => (
            <a key={href} href={href} onClick={() => setOpen(false)} className="py-2.5 font-serif text-xl text-ink">{label}</a>
          ))}
        </div>
      )}
    </header>
  )
}
