// Weak Lockout — T0: no rate-limit / lockout. Dictionary attack on the
// privileged account succeeds within bounded attempts.
//
// T1: the server keys failed-attempt counts off the client IP (X-Forwarded-For
// first hop if present, otherwise the socket address) and locks the source
// after 3 failures for the duration of the deploy. A naive brute force from a
// single source therefore stalls before reaching the real password. The
// bypass cycles the X-Forwarded-For header per attempt — the canonical
// real-world IP-based-lockout bypass. The behaviour module reads the lockout
// key from XFF, so every distinct header value is a fresh source-of-attempts.

export const defences = {
  0: {
    canonicalPayload: () => ({ mode: 'no-spoof' }),
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    // Canonical: brute force WITHOUT spoofing the source IP — the server's
    // IP-based lockout halts the run before the real password is reached.
    canonicalPayload: () => ({ mode: 'no-spoof' }),
    naiveBlockedExpected: true,
    bypassPayloads: [
      // Cycle a distinct X-Forwarded-For per attempt — defeats per-source
      // tracking, brute force completes.
      () => ({ mode: 'rotate-xff' }),
    ],
  },
}

// No generic WAF — T1 lives in behaviour.mjs (per-IP attempt counter).
export function generateT1Config() { return {} }
