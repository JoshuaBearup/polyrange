// Client-side Resource Manipulation — canonical exploit passes a URL
// pointing at an off-origin host whose hostname contains the canary
// (`//x-<canary>.invalid/`). The browser tries to fetch it; the off-origin
// signal records the request URL before resolution fails.
export const defences = {
  0: {
    canonicalPayload: (canary) => `//x-${canary}.invalid/`,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
