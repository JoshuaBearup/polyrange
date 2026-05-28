// Process Timing — canonical exploit submits the secretKey directly; the
// privileged branch delays ~2s and returns the canary body.
export const defences = {
  0: {
    canonicalPayload: (_canary, scenario) => scenario.secretKey,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
