// Authorization bypass — T0. The vuln is a MISSING role check, not a defence to
// evade: any authenticated (signed-up) session reaching the endpoint gets the
// privileged data. No payload — the authenticated request IS the exploit.
// (Forgeable-role escalation is the sibling class, privilege-escalation 4.5.3.)
export const defences = {
  0: {
    canonicalPayload: () => '',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
