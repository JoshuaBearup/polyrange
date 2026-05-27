// LFI — the canonical payload is a php://filter wrapper that base64-exfiltrates
// the source of the PHP config file holding the canary. The decode happens in
// classDef.fireExploit. T0.
export const defences = {
  0: { canonicalPayload: () => 'php://filter/convert.base64-encode/resource=/tmp/app-config.php', naiveBlockedExpected: false, bypassPayloads: [] },
}
