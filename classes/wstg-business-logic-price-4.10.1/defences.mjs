// Price tampering — the canonical exploit submits the restricted item with a
// tampered unit_price (0) so the trusted total is affordable. Chain in fireExploit. T0.
export const defences = {
  0: { canonicalPayload: () => 'price-tamper-0', naiveBlockedExpected: false, bypassPayloads: [] },
}
