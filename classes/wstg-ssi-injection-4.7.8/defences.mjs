// SSI injection — the payload is an #include directive reading the server-side
// canary fragment; the inject+reflect chain lives in classDef.fireExploit. T0.
export const defences = {
  0: { canonicalPayload: () => 'ssi-include-file-read', naiveBlockedExpected: false, bypassPayloads: [] },
}
