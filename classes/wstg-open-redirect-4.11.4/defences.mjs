// Open redirect — the payload is an attacker-controlled off-origin URL carrying
// the canary marker; success = the browser navigates to it (off-origin oracle).
export const defences = {
  0: { canonicalPayload: (canary) => `https://exfil.attacker.example/?c=${canary}`, naiveBlockedExpected: false, bypassPayloads: [] },
}
