import { useI18n, LANGS } from '../lib/i18n.jsx'

export default function LangSwitch({ className = '' }) {
  const { lang, setLang } = useI18n()
  return (
    <div className={`inline-flex items-center rounded-[4px] border border-line-2 ${className}`} role="group" aria-label="Language">
      {LANGS.map(([code, short, full], i) => (
        <button
          key={code}
          type="button"
          onClick={() => setLang(code)}
          aria-label={full}
          aria-current={lang === code ? 'true' : undefined}
          className={`px-2.5 py-1 text-[12px] font-medium transition-colors ${i > 0 ? 'border-l border-line-2' : ''} ${
            lang === code ? 'bg-ink text-obsidian' : 'text-muted hover:text-ink'
          }`}
        >
          {short}
        </button>
      ))}
    </div>
  )
}
