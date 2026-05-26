// OS command injection — per-tier defence contract.
// T1 WAF blocks the common shell metacharacters / command separators a naive
// injection uses (`;`, `|`, `&&`, backtick, `$(`). The bypass uses newline
// command separation, which the metachar rules don't cover — a real sh -c
// treats a newline as a separator, so the injected `env` still runs.
//
// The injection payloads chain a new command onto whatever baseCommand the
// scenario uses (`<host>; env` works whether the base is ping/cat/echo/...),
// and recover the canary by dumping the process environment.

export const RULE_POOL = [
  { name: 'cmdi-semicolon', pattern: ';' },
  { name: 'cmdi-pipe', pattern: '\\|' },
  { name: 'cmdi-and', pattern: '&&' },
  { name: 'cmdi-backtick', pattern: '`' },
  { name: 'cmdi-subshell', pattern: '\\$\\(' },
  { name: 'cmdi-dollar-brace', pattern: '\\$\\{' },
]

// Newline-separated injection — sh runs it as a second command; the metachar
// rules don't match a newline.
export const BYPASS_TEMPLATES = [
  () => '127.0.0.1\nenv',
  () => '127.0.0.1\nprintenv',
]

const naive = () => '127.0.0.1; env'   // uses ';' → blocked by the WAF at T1

export const defences = {
  0: { canonicalPayload: naive, naiveBlockedExpected: false, bypassPayloads: [] },
  1: { canonicalPayload: naive, naiveBlockedExpected: true, bypassPayloads: BYPASS_TEMPLATES },
}

export function generateT1Config(rng = Math.random) {
  // semicolon rule always included so the naive payload is reliably blocked
  const required = ['cmdi-semicolon']
  const optional = RULE_POOL.filter(r => !required.includes(r.name))
  const extra = 2 + Math.floor(rng() * (optional.length - 1))
  const shuffled = [...optional].sort(() => rng() - 0.5)
  const picked = [...RULE_POOL.filter(r => required.includes(r.name)), ...shuffled.slice(0, extra)]
  const styles = ['cloudflare1020', 'awsCloudfront', 'modSecurity', 'generic403', 'fake500', 'silent200']
  return { waf: { rules: picked, blockPageStyle: styles[Math.floor(rng() * styles.length)] } }
}
