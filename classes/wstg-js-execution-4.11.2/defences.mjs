// JavaScript execution — the T1 defence is a CLIENT-SIDE keyword filter on the
// eval input (a server WAF is irrelevant; execution is client-side). T0: raw JS
// runs. T1: the filter rejects the literal "document"; the bypass constructs the
// token by concatenation so the filter misses it.
export const defences = {
  0: {
    canonicalPayload: (canary) => `document.title='${canary}'`,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: (canary) => `document.title='${canary}'`,                 // contains "document" -> filtered
    naiveBlockedExpected: true,
    bypassPayloads: [(canary) => `top['docu'+'ment'].title='${canary}'`],       // assembled token evades the filter
  },
}

// No server-side WAF — the defence is the client-side eval-input filter in
// behaviour.mjs (driven by manifest.defenceTier).
export function generateT1Config() { return {} }
