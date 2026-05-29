// WSTG-INPV-17 — tiered.
//
// T0: forgot-password handler trusts req.headers.host unconditionally. The
//     canonical payload is a Host of the attacker's choosing — any value at
//     all will be embedded in the constructed link.
//
// T1: the handler validates the supplied Host against an allow-list of
//     hostnames the deploy has seen on prior non-vulnerable traffic, but the
//     comparison uses endsWith semantics. Canonical (pure spoof of an
//     unrelated domain) is rejected; bypass is to choose a Host of the form
//     "<random>.<deploy-host>" so the suffix match passes. The constructed
//     link still embeds an attacker-shaped subdomain; the minted token is
//     still valid against the real deploy.
//
// The enforcement and the suffix flaw are class-local conditional logic in
// behaviour.mjs because they depend on a runtime-learned hostname registry
// that a generic regex WAF cannot reference. The exported rule list is empty.

export const RULE_POOL = []

export const defences = {
  0: {
    canonicalPayload: () => 't0-host-spoof',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: () => 't0-host-spoof',
    naiveBlockedExpected: true,
    bypassPayloads: [
      (_canary, _scenario) => 't1-suffix-bypass',
    ],
  },
}

export function generateT1Config() {
  return { waf: { rules: [] } }
}
