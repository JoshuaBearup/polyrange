// User-registration privilege escalation (mass-assignment). The "payload" is
// the privileged account_type value submitted at registration; the registration
// + dashboard-read chain lives in classDef.fireExploit. T0 only — a trust/logic
// flaw, not a payload a generic WAF tier would touch.
export const defences = {
  0: {
    canonicalPayload: () => 'admin',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
