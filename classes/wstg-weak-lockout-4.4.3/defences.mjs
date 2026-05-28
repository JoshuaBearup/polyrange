// Weak Lockout — canonical exploit dictionary-attacks the privileged
// account through the unprotected login endpoint. The right password is
// embedded in candidatePasswords (index 2-15 by schema refinement) so
// the validator finds it within bounded attempts. T0 only.
export const defences = {
  0: {
    canonicalPayload: () => 'brute-force-no-lockout',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
