// WSTG-INFO-01 — tiered.
//
// T0: no defence. The search portal returns the leak entry for any
//     keyword query that overlaps the leaked doc's title/snippet/content.
//     fireExploit issues a bare keyword search using leaked-title words.
//
// T1: the search portal's corpus filter suppresses the leak entry unless
//     the query carries at least one dork operator (site:, inurl:,
//     intitle:, intext:, filetype:) or an exact phrase. Bare keyword
//     queries see only the noise corpus. The bypass = use a dork — the
//     scenario carries a known-working discoveryDork that fireExploit
//     submits at T1. The conditional rule lives in behaviour.mjs because
//     a generic regex WAF cannot express "presence of any of N operators
//     in q=..." cleanly across engine variants; defenceTier on the
//     manifest drives the suppression.

export const RULE_POOL = []

export const defences = {
  0: {
    canonicalPayload: () => 't0-canonical',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: () => 't0-canonical',
    naiveBlockedExpected: true,
    bypassPayloads: [
      (_canary, _scenario) => 't1-bypass',
    ],
  },
}

// T1 here is not a regex WAF — the suppression is class-local conditional
// logic keyed on manifest.defenceTier. Return an empty rule list so the
// generic inspector stays inert at T1.
export function generateT1Config() {
  return { waf: { rules: [] } }
}
