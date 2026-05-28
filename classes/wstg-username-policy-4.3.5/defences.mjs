// Username Policy — canonical exploit signs up with a username crafted
// to collide with the internal reserved name under the scenario's
// normalisation vector (case-fold / whitespace / NFKC). The portal's
// identity check then treats the user as the privileged identity and
// renders the canary-bearing body.
export const defences = {
  0: {
    canonicalPayload: () => 'reserved-name-collision',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
