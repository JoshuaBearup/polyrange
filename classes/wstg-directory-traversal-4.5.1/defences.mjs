// Directory traversal — T0 traverses freely. T1 is a server-side sanitizer that
// strips "../" once; the bypass uses the classic strip-once evasion (....//),
// which leaves a "../" after the single replace. (Not the generic WAF: a regex
// blocking "../" would also catch "....//", so the sanitizer must be intrinsic.)
export const defences = {
  0: {
    canonicalPayload: () => '../.env',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: () => '../.env',          // stripped to ".env" -> not found
    naiveBlockedExpected: true,
    bypassPayloads: [() => '....//.env'],       // strip-once -> "../.env" -> reads the canary
  },
}
export function generateT1Config() { return {} }
