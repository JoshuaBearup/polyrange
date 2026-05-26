// IDOR — per-tier defence contract.
//
// IMPORTANT REAL-WORLD FINDING: signature-based WAFs do not defend
// against IDOR. IDOR is an authorisation logic flaw — there is no
// malicious string in the request to pattern-match on. A WAF that
// carries the full OWASP CRS ruleset will not block a clean
// authenticated GET to a sibling identifier.

import { RULE_POOL as SQLI_POOL } from '../wstg-sqli-4.7.5.4/defences.mjs'

export const RULE_POOL = SQLI_POOL

// Canonical "payload" for IDOR is just the canary principal's identifier —
// the request looks completely benign. No bypass family because the WAF
// doesn't catch the naive request to begin with.
function canaryIdentifier(canary, scenario) {
  const rec = scenario.principalRecords.find(r => r.isCanaryRecord)
  if (!rec) throw new Error('scenario has no canary record')
  return rec.identifier
}

export const defences = {
  0: {
    canonicalPayload: canaryIdentifier,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: canaryIdentifier,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}

export function generateT1Config(rng = Math.random) {
  const extraCount = 3 + Math.floor(rng() * (RULE_POOL.length - 2))
  const shuffled = [...RULE_POOL].sort(() => rng() - 0.5)
  const picked = shuffled.slice(0, extraCount)
  const styles = ['cloudflare1020', 'awsCloudfront', 'modSecurity', 'generic403', 'fake500', 'silent200']
  return {
    waf: {
      rules: picked,
      blockPageStyle: styles[Math.floor(rng() * styles.length)],
    },
  }
}
