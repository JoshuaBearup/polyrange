// Blind XPath injection — tiered.
// T0: no WAF. The blind extraction probes use substring() char-by-char to
//     read the admin account field through the auth/no-auth signal.
// T1: a signature WAF inspects the body and blocks the substring()-keyed probe
//     plus a couple of related blind-XPath idioms. The bypass swaps the
//     character predicate to a different XPath function with the same observable
//     semantics — starts-with(), translate(), contains(), or string-length()
//     for length probing — so the same one-bit oracle still works while the
//     payload no longer matches the rule.

// Sentinel keys driving the extraction strategy in behaviour.fireExploit.
// Keeping the strategy out of the body itself lets a single fireExploit pick
// a probe builder per-attempt without leaking strategy metadata into the body
// the WAF inspects (only the rendered probe is sent, never the sentinel).
export const STRATEGY = {
  SUBSTRING:    'blind:substring',
  STARTS_WITH:  'blind:starts-with',
  SUB_AFTER:    'blind:sub-after',
}

export const RULE_POOL = [
  // The textbook blind-XPath char-by-char probe.
  { name: 'xpath-substring',     pattern: '\\bsubstring\\s*\\(', flags: 'i' },
  // The `or '1'='1` always-true auth-bypass shape (loud, often signature-listed).
  { name: 'xpath-or-tautology',  pattern: "\\bor\\s+'1'\\s*=\\s*'1", flags: 'i' },
  // The `name()` axis probe (used for blind schema enumeration).
  { name: 'xpath-name-axis',     pattern: "\\bname\\s*\\(\\s*\\)", flags: 'i' },
  // The position() axis probe.
  { name: 'xpath-position',      pattern: '\\bposition\\s*\\(\\s*\\)', flags: 'i' },
  // The count() aggregator.
  { name: 'xpath-count',         pattern: '\\bcount\\s*\\(', flags: 'i' },
  // text() node selector inside a predicate (often part of injection-shaped probes).
  { name: 'xpath-text-fn',       pattern: '/text\\s*\\(\\s*\\)', flags: 'i' },
]

export const defences = {
  0: {
    // The sentinel selects substring()-based extraction (the textbook shape).
    canonicalPayload: () => STRATEGY.SUBSTRING,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: () => STRATEGY.SUBSTRING,
    naiveBlockedExpected: true,
    bypassPayloads: [
      () => STRATEGY.STARTS_WITH,
      () => STRATEGY.SUB_AFTER,
    ],
  },
}

export function generateT1Config(rng = Math.random) {
  // Required: the rule that catches substring(). text() in predicates also
  // appears in every probe shape (the query template threads username/text()),
  // so xpath-text-fn would catch every bypass too — keep it out of T1.
  const required = ['xpath-substring']
  const requiredSet = new Set(required)
  // Filter out rules that would block every bypass payload as well.
  const optional = RULE_POOL.filter(r =>
    !requiredSet.has(r.name) && r.name !== 'xpath-text-fn'
  )
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
