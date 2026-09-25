import { createContext, useContext, useEffect, useMemo, useState } from 'react'
import en from '../i18n/en.js'
import pl from '../i18n/pl.js'
import uk from '../i18n/uk.js'

/* English is the site. Polish and Ukrainian are translations offered by a
   button — so the browser's Accept-Language is deliberately NOT consulted. A
   visitor who did not ask for another language gets English, every time, and a
   visitor who did gets their choice remembered. Auto-detection would make the
   page they land on depend on a setting they may not know they have. */

export const LANGS = [
  ['en', 'EN', 'English'],
  ['pl', 'PL', 'Polski'],
  ['uk', 'UK', 'Українська'],
]

const DICTS = { en, pl, uk }
const STORE_KEY = 'aegis.lang'

const Ctx = createContext({ lang: 'en', setLang: () => {}, t: en })

function initial() {
  if (typeof window === 'undefined') return 'en'
  const q = new URLSearchParams(window.location.search).get('lang')
  if (q && DICTS[q]) return q
  try {
    const saved = window.localStorage.getItem(STORE_KEY)
    if (saved && DICTS[saved]) return saved
  } catch {
    /* private mode, blocked storage: English is the right fallback anyway */
  }
  return 'en'
}

export function I18nProvider({ children }) {
  const [lang, setLang] = useState(initial)

  useEffect(() => {
    document.documentElement.lang = lang
    try {
      window.localStorage.setItem(STORE_KEY, lang)
    } catch {
      /* not being able to remember the choice is not a reason to fail */
    }
  }, [lang])

  /* A missing key falls back to English rather than rendering "undefined".
     A half-translated page in a language the reader understands beats a page
     with holes in it, and the gap stays visible to us in the dictionary. */
  const t = useMemo(() => withFallback(DICTS[lang] || en, en), [lang])

  return <Ctx.Provider value={{ lang, setLang, t }}>{children}</Ctx.Provider>
}

function withFallback(dict, base) {
  if (Array.isArray(dict) || typeof dict !== 'object' || dict === null) return dict
  const out = {}
  for (const k of new Set([...Object.keys(base), ...Object.keys(dict)])) {
    const d = dict[k]
    const b = base[k]
    if (d === undefined) out[k] = b
    else if (b && typeof b === 'object' && !Array.isArray(b)) out[k] = withFallback(d || {}, b)
    else out[k] = d
  }
  return out
}

export const useI18n = () => useContext(Ctx)
export const useT = () => useContext(Ctx).t
