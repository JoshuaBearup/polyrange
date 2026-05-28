// Session Puzzling — canonical exploit POSTs the reset form with adminEmail
// to plant the shared session var, then visits the account page which falls
// back to that var and renders the admin's data with the canary. T0 only.
export const defences = {
  0: {
    canonicalPayload: () => 'session-puzzle-cross-flow',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
