import { useState } from 'react'
import { List, X } from '@phosphor-icons/react'
import { Wordmark, GhostButton } from '../lib/ui.jsx'

const NAV = [
  ['Architecture', '#how'],
  ['Controls', '#controls'],
  ['Deployment', '#deployment'],
  ['Compliance', '#compliance'],
  ['Status', '#status'],
]

export default function Nav() {
  const [open, setOpen] = useState(false)
  return (
    <header className="relative z-40 border-b border-line">
      <div className="relative flex h-16 w-full items-center justify-between px-6 md:px-10 lg:px-14">
        <a href="#top" className="z-10"><Wordmark /></a>
        <nav className="absolute left-1/2 hidden -translate-x-1/2 items-center gap-8 md:flex">
          {NAV.map(([t, h]) => (
            <a key={h} href={h} className="text-[14px] text-ink transition-colors hover:text-muted">{t}</a>
          ))}
        </nav>
        <div className="hidden md:block">
          <GhostButton href="#pilot">Start a mirror pilot</GhostButton>
        </div>
        <button className="-mr-2 p-2 text-ink md:hidden" aria-label="Menu" onClick={() => setOpen((v) => !v)}>
          {open ? <X size={20} /> : <List size={20} />}
        </button>
      </div>
      {open && (
        <div className="flex flex-col gap-1 border-t border-line px-6 py-4 md:hidden">
          {[...NAV, ['Start a mirror pilot', '#pilot']].map(([t, h]) => (
            <a key={h} href={h} onClick={() => setOpen(false)} className="py-2.5 font-serif text-xl text-ink">{t}</a>
          ))}
        </div>
      )}
    </header>
  )
}
