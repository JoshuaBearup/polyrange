// HTTP verb tampering — the access control is enforced only on GET. The naive
// GET is "blocked" (403); any other verb skips the filter and reaches the data.
export const defences = {
  0: {
    canonicalPayload: () => 'GET',           // hits the GET-only access filter -> 403
    naiveBlockedExpected: true,
    bypassPayloads: [() => 'POST'],          // alternative verb skips the filter -> protected data
  },
}
