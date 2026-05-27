// Padding oracle — the "payload" is the target account (conventional admin
// username) the forged cookie decrypts to; the oracle attack (recover
// intermediate via padding side-channel, then CBC bit-flip to forge) lives in
// classDef.fireExploit. T0 only — a crypto side-channel, not a WAF-tier payload.
export const defences = {
  0: {
    canonicalPayload: (canary, scenario) => scenario.adminUsername,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
