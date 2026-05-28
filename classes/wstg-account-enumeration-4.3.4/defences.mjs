// Account Enumeration — canonical payload is the privileged username with
// the canary substituted into its structure (the predictable-username-
// structure leak per WSTG). The validator POSTs it with any password;
// the login differential echoes the username (containing canary) back
// in the "wrong password for <username>" branch.
export const defences = {
  0: {
    canonicalPayload: (canary, scenario) =>
      scenario.privilegedUsername.replaceAll('{CANARY}', canary),
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
