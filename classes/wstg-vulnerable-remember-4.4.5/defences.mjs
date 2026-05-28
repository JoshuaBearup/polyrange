// Vulnerable Remember Password — canonical exploit: signup -> GET login
// (drops the demo cookie containing admin credentials) -> decode cookie
// -> POST login with recovered creds -> read privileged area. T0 only.
export const defences = {
  0: {
    canonicalPayload: () => 'demo-cookie-decode',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
