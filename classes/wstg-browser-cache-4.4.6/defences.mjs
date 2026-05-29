// WSTG-ATHN-06 — tiered.
//
// T0: the page cache fronting privilegedPath keys on URL alone. Any
//     anonymous GET after the cache has been populated returns the
//     cached canary.
//
// T1: the cache keys on (path, cookieValue) — anonymous GETs miss.
//     Cache rows never age out by session lifetime, so a captured
//     cookie value still matches its row after the underlying session
//     is logged out / invalidated server-side. The bypass is to
//     capture the cookie value while authenticated, log out, then
//     replay the captured cookie. The conditional lives in
//     handleRequest because it depends on per-deploy scenario fields
//     (cookie name) and on in-process cache state that a generic
//     regex WAF cannot reference.

export const RULE_POOL = []

export const defences = {
  0: {
    canonicalPayload: () => 't0-anonymous-replay',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: () => 't0-anonymous-replay',
    naiveBlockedExpected: true,
    bypassPayloads: [
      (_canary, _scenario) => 't1-captured-cookie',
    ],
  },
}

// T1 enforcement here is not a regex WAF — the cache-key conditional
// is class-local logic in handleRequest, keyed on manifest.defenceTier.
// Returning an empty rule list keeps the generic inspector inert at T1.
export function generateT1Config() {
  return { waf: { rules: [] } }
}
