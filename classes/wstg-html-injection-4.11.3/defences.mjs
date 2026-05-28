// HTML Injection — canonical exploit injects an HTML element carrying the
// canary as text content. The browser oracle finds it via the
// `[data-pr-canary]` element-text check. No JS execution required.
// T0 only initially.
export const defences = {
  0: {
    canonicalPayload: (canary) => `<div data-pr-canary>${canary}</div>`,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
