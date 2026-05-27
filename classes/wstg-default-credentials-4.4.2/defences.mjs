// Default credentials — the admin account keeps an unchanged default password.
export const defences = {
  0: {
    canonicalPayload: (canary, s) => s.defaultPassword,   // the default password; username from the scenario
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
