// Blind XPath injection — the canonical "payload" is the always-true auth bypass
// proving injection; the full canary recovery is a blind char-by-char extraction
// in classDef.fireExploit. T0 only — an injection logic flaw.
export const defences = {
  0: {
    canonicalPayload: () => `' or '1'='1`,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
