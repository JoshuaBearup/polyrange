// SSTI — T0. The vuln is template evaluation of user input; the reference
// exploit dumps the render context object to read the secret field. {{7*7}}
// confirms evaluation; {{site}} dumps the context (incl. the canary). A
// sandboxed-Jinja2 T1 (blocking dunder/attribute access) is a follow-up.
export const defences = {
  0: {
    canonicalPayload: () => '{{site}}',          // dumps the context object -> canary (license_key)
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
