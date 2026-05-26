// XSS — per-tier defence contract: which WAF rules contribute, which
// canonical exploit is "naive", which bypass classes survive each tier.
//
// Rule pool is class-curated (regexes a real WAF would have for XSS).
// Per-deploy: a subset is selected. Bypasses are chosen so AT LEAST ONE
// passes the rule set per construction (validated at deploy time).

export const RULE_POOL = [
  // Catches naive <script>...</script> payloads
  { name: 'xss-script-open',  pattern: '<\\s*script\\b', flags: 'i' },
  { name: 'xss-script-close', pattern: '<\\s*/\\s*script\\s*>', flags: 'i' },
  // Catches javascript: pseudo-protocol
  { name: 'xss-js-protocol',  pattern: 'javascript\\s*:', flags: 'i' },
  // Catches data: URI HTML smuggling
  { name: 'xss-data-html',    pattern: 'data\\s*:\\s*text/html', flags: 'i' },
  // Catches direct eval()
  { name: 'xss-eval-call',    pattern: '\\beval\\s*\\(', flags: 'i' },
  // Catches String.fromCharCode obfuscation
  { name: 'xss-charcode',     pattern: 'String\\.fromCharCode\\s*\\(', flags: 'i' },
  // Catches <iframe src=
  { name: 'xss-iframe',       pattern: '<\\s*iframe\\b', flags: 'i' },
  // Catches expression() CSS-injection
  { name: 'xss-css-expr',     pattern: '\\bexpression\\s*\\(', flags: 'i' },
]

// Bypasses use event handlers on non-script elements. Per construction,
// these do NOT match any rule in RULE_POOL.
export const BYPASS_TEMPLATES = [
  (canary) => `<img src=x onerror="document.title='${canary}'">`,
  (canary) => `<svg onload="document.title='${canary}'">`,
  (canary) => `<body onpageshow="document.title='${canary}'">`,
  (canary) => `<details ontoggle="document.title='${canary}'" open>x</details>`,
]

export const defences = {
  0: {
    // T0 — no defence. The canonical must prove EXECUTION (the browser oracle
    // checks script ran), not mere reflection, so fire a real <script> payload
    // that surfaces the canary via document.title. With no WAF it executes.
    canonicalPayload: (canary) => `<script>document.title='${canary}'</script>`,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    // T1 — naive <script> payload SHOULD be blocked by WAF.
    // Bypass: event handlers on non-script tags survive.
    canonicalPayload: (canary) => `<script>document.title='${canary}'</script>`,
    naiveBlockedExpected: true,
    bypassPayloads: BYPASS_TEMPLATES,
  },
}

// Per-deploy WAF config generator: pick a random rule subset and block-page style.
// Rules are chosen so the canonical naive payload is GUARANTEED blocked
// (script-open is always included).
export function generateT1Config(rng = Math.random) {
  const required = ['xss-script-open']
  const optional = RULE_POOL.filter(r => !required.includes(r.name))
  const extraCount = 3 + Math.floor(rng() * (optional.length - 2))
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
