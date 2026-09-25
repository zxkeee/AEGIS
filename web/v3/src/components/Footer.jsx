import { Wordmark } from '../lib/ui.jsx'

const SOCIALS = [
  ['LinkedIn', 'https://www.linkedin.com/in/nikita-velbovets/', 'M4.98 3.5A2.5 2.5 0 1 0 5 8.5a2.5 2.5 0 0 0 0-5ZM3 9h4v12H3V9Zm7 0h3.8v1.7h.05c.53-.95 1.83-1.95 3.77-1.95 4.03 0 4.78 2.5 4.78 5.75V21h-4v-5.3c0-1.27-.02-2.9-1.9-2.9-1.9 0-2.2 1.37-2.2 2.8V21h-4V9Z'],
  ['GitHub', 'https://github.com/zxkeee', 'M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.9 1.53 2.36 1.09 2.94.83.09-.65.35-1.09.63-1.34-2.22-.25-4.55-1.11-4.55-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.65 0 0 .84-.27 2.75 1.02a9.5 9.5 0 0 1 5 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.38.2 2.4.1 2.65.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85v2.74c0 .27.18.58.69.48A10 10 0 0 0 12 2Z'],
  ['Telegram', 'https://t.me/zxkkke', 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2Zm4.64 6.8-1.65 7.78c-.12.56-.45.7-.92.43l-2.55-1.88-1.23 1.19c-.14.14-.25.25-.51.25l.18-2.6 4.73-4.27c.21-.18-.04-.29-.32-.11L8.7 13.1l-2.52-.79c-.55-.17-.56-.55.11-.82l9.85-3.8c.46-.17.86.11.71.79Z'],
]

export default function Footer() {
  return (
    <footer className="border-t border-line bg-obsidian py-12">
      <div className="mx-auto flex max-w-6xl flex-col items-start justify-between gap-6 px-6 sm:flex-row sm:items-center">
        <Wordmark />
        <p className="max-w-sm text-[13px] leading-relaxed text-muted">
          Self-hosted API security gateway, built in Go. Your hardware, your
          database, no traffic leaving your network. Seeking design partners.
        </p>
        <div className="flex gap-2">
          {SOCIALS.map(([lab, href, d]) => (
            <a key={lab} href={href} target="_blank" rel="noopener" aria-label={lab} className="grid h-9 w-9 place-items-center rounded-[4px] border border-line-2 text-muted transition-colors hover:border-ink hover:text-ink">
              <svg viewBox="0 0 24 24" fill="currentColor" className="h-4 w-4"><path d={d} /></svg>
            </a>
          ))}
        </div>
      </div>
    </footer>
  )
}
