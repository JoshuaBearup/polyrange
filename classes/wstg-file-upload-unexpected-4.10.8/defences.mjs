// Unexpected file type — the chain (spoof Content-Type: image/png to bypass the
// type filter, upload a .php, request it to execute) lives in fireExploit. T0.
export const defences = {
  0: { canonicalPayload: () => 'content-type-spoof-php', naiveBlockedExpected: false, bypassPayloads: [] },
}
