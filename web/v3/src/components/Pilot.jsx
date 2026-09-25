import { useState } from 'react'
import { Reveal, SectionHeader, GhostButton } from '../lib/ui.jsx'

const CONTACT = 'n.velbovetss@gmail.com'

export default function Pilot() {
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)

  async function onSubmit(e) {
    e.preventDefault()
    const f = e.currentTarget
    if (!f.checkValidity()) { f.reportValidity(); return }
    const d = Object.fromEntries(new FormData(f).entries())
    const message = d.interest ? `Interested in: ${d.interest}\n\n${d.message || ''}`.trim() : d.message
    const payload = { name: d.name, email: d.email, company: d.company, scale: d.scale, message }
    setBusy(true); setNote('Sending...')
    try {
      const r = await fetch('/api/pilot', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
      if (!r.ok) throw new Error()
      f.reset(); setNote('Thank you, we will be in touch within a day.')
    } catch {
      const body = `Name: ${d.name}\nEmail: ${d.email}\nCompany: ${d.company || 'n/a'}\nInterested in: ${d.interest || 'n/a'}\nTraffic: ${d.scale || 'n/a'}\n\n${d.message || ''}`
      window.location.href = `mailto:${CONTACT}?subject=${encodeURIComponent('AEGIS pilot request - ' + (d.company || d.name))}&body=${encodeURIComponent(body)}`
      setNote('Opening your email client...')
    } finally { setBusy(false) }
  }

  const field = 'flex flex-col gap-2'
  const input = 'w-full rounded-[4px] border border-line-2 bg-card px-3.5 py-2.5 text-[14px] text-ink outline-none transition-colors focus:border-accent focus:ring-2 focus:ring-accent/30'
  const lab = 'text-[13px] font-medium text-muted'

  return (
    <section id="pilot" className="border-t border-line py-16 md:py-20 scroll-mt-16">
      <div className="grid gap-12 lg:grid-cols-2 lg:gap-16">
        <Reveal>
          <SectionHeader
            title="Run AEGIS on a copy of your traffic for a week."
            sub="Your proxy mirrors each request to us. We are not in the path, we never touch a response, and stopping the gateway mid-pilot changes nothing for your users. At the end you get a findings report: the shadow APIs, the endpoints leaking data, and who is calling them."
          />
          <ul className="mt-6 flex flex-col gap-2 text-[13.5px] text-muted">
            {[
              'One week, mirror mode, no cost',
              'Nothing in your request path, nothing to roll back',
              'Findings mapped to NIS2, DORA and ISO 27001',
              'Runs on your hardware — no traffic leaves your network',
            ].map((t) => (
              <li key={t} className="flex gap-2.5"><span className="mt-[8px] h-1 w-1 flex-none rounded-full bg-accent" />{t}</li>
            ))}
          </ul>
        </Reveal>

        <Reveal delay={0.08}>
          <form onSubmit={onSubmit} noValidate className="grid grid-cols-1 gap-5 rounded-2xl border border-line-2 bg-card p-6 sm:grid-cols-2 sm:p-7">
            <div className={field}><label className={lab} htmlFor="name">Name</label><input id="name" name="name" required autoComplete="name" className={input} /></div>
            <div className={field}><label className={lab} htmlFor="email">Work email</label><input id="email" name="email" type="email" required autoComplete="email" className={input} /></div>
            <div className={field}><label className={lab} htmlFor="company">Company</label><input id="company" name="company" autoComplete="organization" className={input} /></div>
            <div className={field}>
              <label className={lab} htmlFor="interest">I am interested in</label>
              <select id="interest" name="interest" className={`${input} [&>option]:bg-card`}>
                <option value="">Select...</option>
                <option>Running a pilot</option>
                <option>An enterprise demo</option>
                <option>Investing or partnering</option>
              </select>
            </div>
            <div className={`${field} col-span-2`}>
              <label className={lab} htmlFor="message">Anything we should know? <span className="text-faint">optional</span></label>
              <textarea id="message" name="message" rows={3} className={`${input} resize-y`} />
            </div>
            <div className="col-span-2 flex flex-wrap items-center gap-5">
              <GhostButton type="submit" disabled={busy} className="disabled:opacity-50">
                Start a mirror pilot
              </GhostButton>
              <p className="text-[12.5px] text-muted" role="status" aria-live="polite">{note}</p>
            </div>
          </form>
        </Reveal>
      </div>
    </section>
  )
}
