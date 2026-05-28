// SQLi data extraction — tiered.
// T0: no WAF; the canonical UNION SELECT pulls the vault rows directly.
// T1: a WAF blocks UNION comprehensively (incl comment-splitting via the
//     u\W*n\W*i\W*o\W*n pattern), so NO direct extraction works — the only way
//     to reach the vault canary is a blind boolean subquery oracle. The
//     reference fireExploit tries UNION first, then falls back to blind.

// Shared pool of signature SQLi WAF rules — imported by 15 other classes' T1
// configs as decoy rules. Kept here for backwards compatibility.
export const RULE_POOL = [
  { name: 'sqli-union-select',  pattern: '\\bunion\\s+(all\\s+)?select\\b', flags: 'i' },
  { name: 'sqli-or-tautology',  pattern: "\\bor\\s+'?\\w+'?\\s*=\\s*'?\\w+'?", flags: 'i' },
  { name: 'sqli-stacked',       pattern: ';\\s*(select|insert|update|delete|drop)\\b', flags: 'i' },
  { name: 'sqli-sleep',         pattern: '\\bsleep\\s*\\(', flags: 'i' },
  { name: 'sqli-benchmark',     pattern: '\\bbenchmark\\s*\\(', flags: 'i' },
  { name: 'sqli-info-schema',   pattern: '\\binformation_schema\\b', flags: 'i' },
  { name: 'sqli-quote-comment', pattern: "'\\s*--", flags: 'i' },
  { name: 'sqli-hex',           pattern: '0x[0-9a-f]{6,}', flags: 'i' },
]

export const defences = {
  0: {
    canonicalPayload: (canary, scenario) => `zzx' UNION SELECT id, account, secret FROM ${scenario.sensitiveTable} -- `,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    // fireExploit ignores this string and auto-falls-back to blind extraction.
    canonicalPayload: () => 'blind-boolean-extraction',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}

export function generateT1Config(rng = Math.random) {
  const styles = ['cloudflare1020', 'awsCloudfront', 'modSecurity', 'generic403', 'fake500', 'silent200']
  return {
    waf: {
      // Blocks UNION even with comment/whitespace splitting (un/**/ion, u n i o n).
      rules: [{ name: 'sqli-union', pattern: 'u\\W*n\\W*i\\W*o\\W*n', flags: 'i' }],
      blockPageStyle: styles[Math.floor(rng() * styles.length)],
    },
  }
}
