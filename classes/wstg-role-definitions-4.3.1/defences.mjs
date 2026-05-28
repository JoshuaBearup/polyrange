// Role Definitions — canonical exploit signs up as the over-permitted role
// and GETs its over-permitted dataset. The dataset's row population includes
// the canary, recovered via substring on the rendered rows. T0 only.
export const defences = {
  0: {
    canonicalPayload: () => 'role-overscope',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
