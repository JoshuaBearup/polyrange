// Misuse Defenses — canonical exploit fires `abuseThreshold + 1` obviously-
// malicious submissions against the live endpoint; because no rate-limit,
// no lockout, no payload filter ever reacts (the bug), the server-side
// counter accumulates and the diagnostic-queue response surfaces the canary.
// T0 only.
export const defences = {
  0: {
    canonicalPayload: () => 'sustained-abuse-no-defense',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
