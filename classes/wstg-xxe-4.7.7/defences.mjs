// XXE — the "payload" is a DOCTYPE external-entity document reading the
// server-side canary file; the read+reflect chain lives in classDef.fireExploit.
// T0 only — an XML-parser misconfiguration (external entities enabled).
export const defences = {
  0: {
    canonicalPayload: () => 'xxe-file-read',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
