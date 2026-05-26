// Per-deploy anchor for file-extension-handling exposure (4.2.3) — fixes which
// source-file backup/alternate extension carries the canary.

import crypto from 'node:crypto'

export const EXT_POOL = [
  'a .bak copy of a server-side source file served as plain text (source disclosure)',
  'an editor swap/backup file (.swp, .swo, or trailing ~) of a source file',
  'a .old / .orig / .save copy of a config or source file served as text',
  'a source file with a mishandled double extension (e.g. app.php.txt) served as text instead of executed',
  'an .inc include file served as plain text, leaking server-side code',
  'a .dist / .sample config template that still contains real values',
  'a renamed source file (e.g. index.php.bak) revealing server-side logic',
]

export function pickAnchor() {
  return 'The canary lives in ' + EXT_POOL[crypto.randomBytes(1)[0] % EXT_POOL.length] +
    '. The body must be the SOURCE/TEXT of that file (served unexecuted), with pr_<canary> as a natural value in the code/config. Include 2-4 other mishandled-extension files as decoys.'
}
