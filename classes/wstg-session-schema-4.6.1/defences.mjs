// Session schema — the token is base64("user:<name>") with no integrity check,
// so it is trivially forgeable. The reference exploit forges the admin's token.
export const defences = {
  0: {
    canonicalPayload: (canary, s) => Buffer.from('user:' + s.adminUsername).toString('base64'),
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
