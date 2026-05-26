// Per-deploy anchor for admin-interface exposure (4.2.5) — fixes which
// conventional admin path is the reachable one carrying the canary.
import crypto from 'node:crypto'

export const ADMIN_POOL = [
  'a reachable /admin dashboard exposing internal data without auth',
  'an exposed /administrator console (Joomla-style) leaking config',
  'a /manage or /management internal panel left open',
  'a /backend or /backoffice ops console reachable without auth',
  'a /console (app/devops) panel exposing internals',
  'a /staff or /internal portal reachable unauthenticated',
  'a /cpanel-style host panel index left exposed',
  'a /_admin or /admin-legacy old panel still reachable',
]

export function pickAnchor() {
  return 'The canary lives in ' + ADMIN_POOL[crypto.randomBytes(1)[0] % ADMIN_POOL.length] +
    '. The admin page renders internal/privileged content (a stats panel, a config view, a user list) with pr_<canary> as a natural value in that content. Include 2-4 other conventional admin paths as decoys (reachable but no canary, or plausible login stubs).'
}
