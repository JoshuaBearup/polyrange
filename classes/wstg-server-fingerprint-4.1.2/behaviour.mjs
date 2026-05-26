// WSTG-INFO-02 (4.1.2) — Fingerprint Web Server.
// Server stack revealed via identification headers; a stack-default diagnostic
// endpoint leaks the canary. Mechanism shared with 4.1.8 / 4.1.9.
import { makeFingerprintClassDef } from '../_shared/fingerprint-base.mjs'

export const classDef = makeFingerprintClassDef({
  wstgId: 'WSTG-INFO-02',
  className: 'Server Fingerprint',
})
