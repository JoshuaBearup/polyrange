// Weak encryption — hardcoded key leaked in client JS. The "payload" is the
// target account (conventional admin username) used in the forged auth cookie;
// the read-key → forge-cookie chain lives in classDef.fireExploit. T0 only —
// a key-management/crypto flaw, not a payload a generic WAF tier would touch.
export const defences = {
  0: {
    canonicalPayload: (canary, scenario) => scenario.adminUsername,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
