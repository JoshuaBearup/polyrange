// Weak password reset — broken token↔account binding. The "payload" is simply
// the target account (the conventional admin username); the multi-step takeover
// chain lives in classDef.fireExploit. T0 only — this is a logic/authorization
// flaw, not a payload a generic WAF tier would touch.
export const defences = {
  0: {
    canonicalPayload: (canary, scenario) => scenario.adminUsername,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
