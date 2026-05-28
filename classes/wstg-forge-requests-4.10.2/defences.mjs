// Forge Requests — canonical exploit POSTs the privileged routing value
// (revealed by the leaked HTML comment) and the server-trusted handler
// returns the internal response carrying the canary. T0 only.
export const defences = {
  0: {
    canonicalPayload: () => 'forge-priv-option',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
