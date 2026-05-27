// IMAP injection — the payload CRLF-injects extra IMAP commands into the
// message-id to SELECT + FETCH the admin mailbox. The full chain (decode +
// socket commands) lives in classDef.fireExploit. T0.
export const defences = {
  0: { canonicalPayload: () => 'imap-crlf-mailbox-read', naiveBlockedExpected: false, bypassPayloads: [] },
}
