// Workflow circumvention — the exploit forges the checkout_stage cookie to
// "complete", reaching fulfilment without payment. Chain in fireExploit. T0.
export const defences = {
  0: { canonicalPayload: () => 'forge-stage-complete', naiveBlockedExpected: false, bypassPayloads: [] },
}
