// Malicious file upload — the chain (upload a PHP web shell, then request it to
// execute and dump the canary) lives in classDef.fireExploit. T0.
export const defences = {
  0: { canonicalPayload: () => 'upload-php-webshell', naiveBlockedExpected: false, bypassPayloads: [] },
}
