// CORS misconfiguration — the canonical exploit signs up and fetches the API
// with Origin: null; the buggy allow-list accepts it and returns the canary.
// T0 only.
export const defences = {
  0: {
    canonicalPayload: () => 'cors-null-origin',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
