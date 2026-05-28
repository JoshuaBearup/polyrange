// HTTP verb tampering — the access control is enforced only on GET. The naive
// canonical hits the GET-only filter; non-GET verbs slip past and reach the
// data.
//
// T1: the handler additionally blocks the privileged non-GET verb in the
// request line (a typical middleware "lock down dangerous methods" stance).
// The bypass uses a permitted verb (POST) and tunnels the privileged verb
// through the standard method-override header. The behaviour layer honours
// the override header at T1, so the request resolves to the privileged verb
// internally and the GET-only access filter is again skipped.
export const defences = {
  0: {
    canonicalPayload: () => ({ method: 'GET' }),           // hits the GET-only filter -> 403
    naiveBlockedExpected: true,
    bypassPayloads: [
      () => ({ method: 'POST' }),                          // non-GET skips the filter -> data
    ],
  },
  1: {
    // At T1 the server blocks the privileged method in the request line too.
    // Sending POST directly is "the canonical T1 attempt" and is now blocked.
    canonicalPayload: () => ({ method: 'POST' }),
    naiveBlockedExpected: true,
    bypassPayloads: [
      // Permitted verb in the request line, privileged verb tunnelled via the
      // common override header — the middleware bypass pattern.
      () => ({ method: 'GET', overrideHeader: 'X-HTTP-Method-Override', overrideValue: 'POST' }),
    ],
  },
}

// No generic WAF rules — the T1 defence is behavioural (block non-GET in the
// request line, but trust the method-override header) and lives in
// behaviour.mjs. Returning an empty config keeps the generic inspector inert.
export function generateT1Config() { return {} }
