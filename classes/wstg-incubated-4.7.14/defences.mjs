// Incubated Vulnerability — canonical exploit submits a report with the
// privileged category, then visits the per-report view URL where the admin
// auto-reply (carrying the canary) is rendered. T0 only.
export const defences = {
  0: {
    canonicalPayload: () => 'incubate-priv-category',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
