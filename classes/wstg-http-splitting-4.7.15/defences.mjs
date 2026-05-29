// WSTG-INPV-15 — tiered.
//
// T0: neither user-controlled header slot is filtered. Splitting via the
//     destination parameter on the redirect handler trivially surfaces
//     the canary-bearing X-Internal-Token header as response body bytes.
//
// T1: the redirect handler strips \r and \n from the destination
//     parameter before concatenating into Location, so the T0 payload
//     is squashed flat. BUT the preferences handler still writes the
//     `name` and `value` query parameters raw into Set-Cookie. Splitting
//     through the preference-name slot bypasses the partial filter and
//     surfaces the same X-Internal-Token canary the same way.
//
// Both tier enforcements are class-local conditional logic in
// behaviour.mjs (the filter sits inside handleRequest, keyed off
// manifest.defenceTier). A generic regex WAF cannot model a "filter CR
// and LF out of one query param but not another" rule, so RULE_POOL is
// empty and generateT1Config emits no rules.

export const RULE_POOL = []

export const defences = {
  0: {
    canonicalPayload: () => 't0-redirect-split',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: () => 't0-redirect-split',
    naiveBlockedExpected: true,
    bypassPayloads: [
      (_canary, _scenario) => 't1-pref-split',
    ],
  },
}

export function generateT1Config() {
  return { waf: { rules: [] } }
}
