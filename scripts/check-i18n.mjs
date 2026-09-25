#!/usr/bin/env node
/* Fail when the translation dictionaries stop having the same shape.
 *
 * The runtime falls back to English for a missing key, which is the right
 * behaviour for a visitor — a page with one English paragraph beats a page
 * with the word "undefined" in it. It is the wrong behaviour for us: the gap
 * is invisible, so a Polish page can quietly drift back into English one key
 * at a time and nobody finds out until somebody who reads Polish looks.
 *
 * Shape, not content: this cannot tell whether a translation is GOOD. It tells
 * whether it is THERE, and that a list has the same number of entries, because
 * a three-item list rendered from a two-item translation drops a row silently.
 */

import en from '../web/v3/src/i18n/en.js'
import pl from '../web/v3/src/i18n/pl.js'
import uk from '../web/v3/src/i18n/uk.js'

const LANGS = { pl, uk }

function shape(value, path = '') {
  if (Array.isArray(value)) {
    return [`${path}[len=${value.length}]`, ...value.flatMap((v, i) => shape(v, `${path}[${i}]`))]
  }
  if (value && typeof value === 'object') {
    return Object.keys(value).sort().flatMap((k) => shape(value[k], path ? `${path}.${k}` : k))
  }
  return [path]
}

function untranslated(base, dict, path = '') {
  // A string identical to the English one is usually a key somebody copied and
  // never translated. Short strings and bare identifiers are excluded: "AEGIS",
  // "NIS2", "DORA", "BOLA / BFLA" and a URL fragment are supposed to match.
  if (typeof base === 'string' && typeof dict === 'string') {
    if (base === dict && base.length > 24 && /\s/.test(base)) return [path]
    return []
  }
  if (Array.isArray(base) && Array.isArray(dict)) {
    return base.flatMap((v, i) => (i < dict.length ? untranslated(v, dict[i], `${path}[${i}]`) : []))
  }
  if (base && dict && typeof base === 'object' && typeof dict === 'object') {
    return Object.keys(base).flatMap((k) =>
      k in dict ? untranslated(base[k], dict[k], path ? `${path}.${k}` : k) : [])
  }
  return []
}

const enShape = new Set(shape(en))
const failures = []

for (const [name, dict] of Object.entries(LANGS)) {
  const got = new Set(shape(dict))
  const missing = [...enShape].filter((k) => !got.has(k))
  const extra = [...got].filter((k) => !enShape.has(k))

  if (missing.length) {
    failures.push(
      `${name}.js: ${missing.length} key(s) the English dictionary has and this one does not. ` +
      `Each renders as English at runtime with no warning:\n` +
      missing.slice(0, 12).map((k) => `      ${k}`).join('\n') +
      (missing.length > 12 ? `\n      ... and ${missing.length - 12} more` : ''))
  }
  if (extra.length) {
    failures.push(
      `${name}.js: ${extra.length} key(s) English does not have. Either English lost a ` +
      `string that should still be on the page, or this is a leftover nothing reads:\n` +
      extra.slice(0, 12).map((k) => `      ${k}`).join('\n'))
  }

  const same = untranslated(en, dict)
  if (same.length) {
    failures.push(
      `${name}.js: ${same.length} string(s) are byte-identical to the English text. ` +
      `That is a copied key, not a translation:\n` +
      same.slice(0, 12).map((k) => `      ${k}`).join('\n'))
  }
}

if (failures.length) {
  console.log('ERROR: the translation dictionaries disagree.\n')
  for (const f of failures) console.log(`  ${f}\n`)
  console.log(`check-i18n: FAILED (${failures.length} finding(s))`)
  process.exit(1)
}

console.log(`check-i18n: OK (${Object.keys(LANGS).length} translations, ${enShape.size} keys each)`)
