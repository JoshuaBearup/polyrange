// WSTG-ATHN-11 — tiered.
//
// T0: portalPath omits the mfa_verified check entirely. Once a session
//     exists (signup + login), GET portalPath returns the canary.
//
// T1: portalPath enforces mfa_verified. BUT a debug-header allowlist
//     bypass remains in place from staging — a specific HTTP header at
//     a specific value skips the check. The header name and value leak
//     via a stale HTML comment inserted into the homepage decoy by the
//     decorateDecoys hook (T1 only). The bypass conditional lives in
//     behaviour.mjs because it depends on per-deploy scenario fields
//     that a generic regex WAF cannot reference.

export const RULE_POOL = []

export const defences = {
  0: {
    canonicalPayload: () => 't0-forced-browse',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: () => 't0-forced-browse',
    naiveBlockedExpected: true,
    bypassPayloads: [
      (_canary, _scenario) => 't1-bypass-header',
    ],
  },
}

// T1 here is not a regex WAF — the enforcement and the bypass-header
// recognition are class-local conditional logic in handleRequest, keyed
// on manifest.defenceTier. Returning an empty rule list keeps the
// generic inspector inert at T1.
export function generateT1Config() {
  return { waf: { rules: [] } }
}
