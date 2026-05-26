// Privilege escalation — T0. The vuln is the server trusting a client-supplied
// role/profile/tier field: forging it to the privileged value escalates. No
// defence to evade at T0 — the forge IS the exploit. (A signed/encoded role
// token would be a future T1.)
export const defences = {
  0: {
    // Reference exploit: send the privileged role value in the role slot.
    canonicalPayload: (canary, scenario) => scenario.privilegedValue,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
