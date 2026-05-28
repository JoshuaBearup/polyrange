// Unexpected file type — T0: spoof Content-Type: image/png with a bare PHP
// body bypasses the type filter; php -S executes the unexpected file.
//
// T1: the backend also sniffs the body's first bytes against a list of real
// image-format magics. The bare-PHP-with-spoofed-CT body fails the sniff.
// The bypass is a polyglot whose first bytes are a valid GIF89a header
// followed by the PHP block — the magic sniff passes, php -S still executes
// the file (the engine parses <?php...?> anywhere in the body), and the
// canary surfaces.
export const defences = {
  0: {
    canonicalPayload: () => ({ mode: 'plain' }),
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: () => ({ mode: 'plain' }),     // T1 sniff rejects
    naiveBlockedExpected: true,
    bypassPayloads: [
      () => ({ mode: 'polyglot' }),                  // GIF89a + PHP
    ],
  },
}

// No generic WAF — the T1 control sits inside the PHP backend.
export function generateT1Config() { return {} }
