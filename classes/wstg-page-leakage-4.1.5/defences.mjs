// Page-content leakage — per-tier defence contract.
// A signature WAF does not defend against reading an ordinary page's source.
// The naive recon (GET the page, read source) succeeds at T0 and T1. The real
// mitigation is "don't leave secrets in markup" — not a payload filter.

import { RULE_POOL as SQLI_POOL } from '../wstg-sqli-4.7.5.4/defences.mjs'

export const RULE_POOL = SQLI_POOL

export const defences = {
  0: { naiveBlockedExpected: false, bypassPayloads: [] },
  1: { naiveBlockedExpected: false, bypassPayloads: [] },
}

export function generateT1Config(rng = Math.random) {
  const extraCount = 3 + Math.floor(rng() * (RULE_POOL.length - 2))
  const shuffled = [...RULE_POOL].sort(() => rng() - 0.5)
  const picked = shuffled.slice(0, extraCount)
  const styles = ['cloudflare1020', 'awsCloudfront', 'modSecurity', 'generic403', 'fake500', 'silent200']
  return { waf: { rules: picked, blockPageStyle: styles[Math.floor(rng() * styles.length)] } }
}
