// SSRF — per-tier defence contract.
// T1 WAF blocks the obvious loopback strings in the request (127.0.0.1,
// localhost). The bypass reaches the SAME loopback service via an alternate
// host encoding the string-filter doesn't catch — IPv6 loopback [::1], or a
// "localhost domain" that resolves to 127.0.0.1. Both still pass the egress
// guard (they resolve to loopback), so they reach the internal service.

export const RULE_POOL = [
  { name: 'ssrf-loopback-v4', pattern: '127\\.0\\.0\\.1' },
  { name: 'ssrf-localhost', pattern: 'localhost', flags: 'i' },
  { name: 'ssrf-anyaddr', pattern: '0\\.0\\.0\\.0' },
  { name: 'ssrf-metadata', pattern: '169\\.254\\.169\\.254' },
]

const internalUrl = (s, host = '127.0.0.1') => `http://${host}:${s.internalPort}${s.internalPath}`

export const defences = {
  0: {
    // T0 — no defence; fetch the internal service directly via loopback.
    canonicalPayload: (canary, s) => internalUrl(s, '127.0.0.1'),
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    // T1 — literal loopback blocked; bypass via IPv6 loopback or a localhost-domain.
    canonicalPayload: (canary, s) => internalUrl(s, '127.0.0.1'),
    naiveBlockedExpected: true,
    bypassPayloads: [
      (canary, s) => internalUrl(s, '[::1]'),          // IPv6 loopback
      (canary, s) => internalUrl(s, 'localtest.me'),   // resolves to 127.0.0.1
    ],
  },
}

export function generateT1Config(rng = Math.random) {
  const required = ['ssrf-loopback-v4', 'ssrf-localhost']
  const req = RULE_POOL.filter(r => required.includes(r.name))
  const opt = RULE_POOL.filter(r => !required.includes(r.name))
  const extra = Math.floor(rng() * (opt.length + 1))
  const picked = [...req, ...[...opt].sort(() => rng() - 0.5).slice(0, extra)]
  const styles = ['cloudflare1020', 'awsCloudfront', 'modSecurity', 'generic403', 'fake500', 'silent200']
  return { waf: { rules: picked, blockPageStyle: styles[Math.floor(rng() * styles.length)] } }
}
