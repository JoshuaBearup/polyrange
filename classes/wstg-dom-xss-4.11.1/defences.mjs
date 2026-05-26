// DOM XSS — the T1 defence is a CLIENT-SIDE sanitizer (in the page JS), because
// the payload is in the URL fragment and never reaches the server (a server WAF
// is useless by construction — the WSTG point). T0: the onerror payload fires.
// T1: the client sanitizer strips onerror (canonical no longer fires); the
// bypass uses svg onload, which the sanitizer misses.
export const defences = {
  0: {
    canonicalPayload: (canary) => `<img src=x onerror="document.title='${canary}'">`,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: (canary) => `<img src=x onerror="document.title='${canary}'">`,
    naiveBlockedExpected: true,
    bypassPayloads: [(canary) => `<svg onload="document.title='${canary}'">`],
  },
}

// No server-side WAF — the defence is the client-side sanitizer in behaviour.mjs
// (driven by manifest.defenceTier). Empty config keeps the generic inspector a no-op.
export function generateT1Config() { return {} }
