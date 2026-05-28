// Malicious file upload — the chain (upload a PHP web shell, then request it to
// execute and dump the canary) lives in classDef.fireExploit. T0.
//
// T1 attempted (extension blocklist + magic-byte sniff, polyglot-with-alt-ext
// bypass) but the php -S router dispatch path for non-.php extensions wasn't
// reliable enough on the deploy substrate within the iteration budget — see
// constraints.md for the postmortem. The class is T0-only for now; the
// adjacent class wstg-file-upload-unexpected-4.10.8 carries the magic-byte-
// sniff + GIF89a-polyglot bypass at T1 (the .php execution path works there,
// because the blocklist is absent).
export const defences = {
  0: { canonicalPayload: () => 'upload-php-webshell', naiveBlockedExpected: false, bypassPayloads: [] },
}
