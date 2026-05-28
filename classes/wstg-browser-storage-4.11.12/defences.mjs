// Browser Storage — canonical exploit loads the page with the canary as
// the token query parameter; the inline init script persists it to
// localStorage, where the browser oracle's localStorage scan finds it.
export const defences = {
  0: {
    canonicalPayload: (canary) => canary,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
