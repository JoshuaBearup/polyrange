// Session Fixation is structurally T0-only. The bug is the absence of
// session-id rotation at the authentication boundary, and a working T1
// defence would simply rotate the cookie — there is no meaningful
// bypass path that survives that rotation while still demonstrating the
// fixation pattern. Documenting this rather than building a stretchy
// pseudo-T1.
export const defences = {
  0: {
    canonicalPayload: () => 'fix-cookie-pre-signup',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
