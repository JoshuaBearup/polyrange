// XSSI — the canonical exploit signs up, then fetches scriptPath with the
// session cookie; the returned JS body carries the canary embedded in a
// `window.<Global> = {…}` assignment. T0 only.
export const defences = {
  0: {
    canonicalPayload: () => 'xssi-script-include',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
