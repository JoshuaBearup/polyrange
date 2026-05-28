// Integrity Checks — canonical exploit forges a token swapping the sku to the
// privileged value with any garbage signature suffix; the server never
// validates the signature. T0 only.
export const defences = {
  0: {
    canonicalPayload: () => 'integrity-forge-token',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
