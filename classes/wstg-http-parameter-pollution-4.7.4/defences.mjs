// HTTP parameter pollution — filter/backend parsing mismatch (intrinsic to the
// class, not the generic WAF). T0: no filter, the privileged value works
// directly. T1: the filter blocks the privileged value as the FIRST occurrence;
// the bypass duplicates the param (allowed-first → filter passes, privileged-
// last → backend acts on it).
const param = (s, ...vals) => vals.map(v => `${encodeURIComponent(s.paramName)}=${encodeURIComponent(v)}`).join('&')

export const defences = {
  0: {
    canonicalPayload: (canary, s) => param(s, s.restrictedValue),
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: (canary, s) => param(s, s.restrictedValue),            // single → filter blocks (first occ)
    naiveBlockedExpected: true,
    bypassPayloads: [(canary, s) => param(s, s.allowedValue, s.restrictedValue)], // HPP: allowed-first, restricted-last
  },
}

// No generic WAF — the defence is the intrinsic first-vs-last parsing mismatch
// in behaviour.mjs (driven by manifest.defenceTier). Returning an empty config
// keeps the generic inspector a no-op at T1.
export function generateT1Config() { return {} }
