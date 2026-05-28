// Function Usage Limits — canonical exploit sets the client-trusted counter
// cookie directly to the unlock threshold, bypassing the intended N-step
// progression. T0 only.
export const defences = {
  0: {
    canonicalPayload: () => 'usage-cookie-set',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
