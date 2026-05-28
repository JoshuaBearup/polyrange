// HTML Injection — tiered.
// T0: no WAF; canonical `<div data-pr-canary>` lands in the DOM directly.
// T1: WAF blocks the canonical via a tag-open regex. Bypass via alt tag
//     names (SVG, MathML namespace tags, deprecated-but-still-rendered
//     containers) which the WAF doesn't list. The data-pr-canary attribute
//     stays present; browser oracle still locates it.

export const RULE_POOL = [
  { name: 'html-div-open',    pattern: '<\\s*div\\b',    flags: 'i' },
  { name: 'html-span-open',   pattern: '<\\s*span\\b',   flags: 'i' },
  { name: 'html-iframe-open', pattern: '<\\s*iframe\\b', flags: 'i' },
  { name: 'html-script-open', pattern: '<\\s*script\\b', flags: 'i' },
  { name: 'html-event-attr',  pattern: '\\bon\\w+\\s*=', flags: 'i' },
]

export const BYPASS_TEMPLATES = [
  (canary) => `<svg data-pr-canary>${canary}</svg>`,
  (canary) => `<math data-pr-canary>${canary}</math>`,
  (canary) => `<details data-pr-canary>${canary}</details>`,
  (canary) => `<summary data-pr-canary>${canary}</summary>`,
  (canary) => `<marquee data-pr-canary>${canary}</marquee>`,
]

export const defences = {
  0: {
    canonicalPayload: (canary) => `<div data-pr-canary>${canary}</div>`,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: (canary) => `<div data-pr-canary>${canary}</div>`,
    naiveBlockedExpected: true,
    bypassPayloads: BYPASS_TEMPLATES,
  },
}

export function generateT1Config(rng = Math.random) {
  const required = ['html-div-open']
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
