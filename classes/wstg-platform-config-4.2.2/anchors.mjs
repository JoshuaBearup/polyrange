// Per-deploy anchor for platform-config exposure (4.2.2) — fixes WHICH
// conventionally-exposed platform artifact carries the canary, so deploys
// spread across the real set of "files that should never be web-reachable".

import crypto from 'node:crypto'

export const ARTIFACT_POOL = [
  'a leaked /.env file with environment variables (DB creds, API keys, secrets)',
  'an exposed /.git/config (and the implied repo) revealing remotes and internals',
  'a /phpinfo.php dump exposing the full PHP environment',
  'an exposed /web.config (.NET) with connection strings / appSettings',
  'an exposed /appsettings.json (.NET Core) with secrets',
  'a reachable /config.json or /config.yml with internal settings',
  'an exposed /docker-compose.yml revealing services and env',
  'a leaked /.npmrc or /.pypirc with a registry auth token',
  'an exposed /.aws/credentials or cloud credential file',
  'a reachable /wp-config.php backup with DB credentials',
  'an exposed /.htaccess / .htpasswd pair',
  'a /server-info or /.well-known/ debug dump for the platform',
  'an exposed /Dockerfile + build args revealing internals',
  'a reachable /.vscode/ or /.idea/ project config leaking paths',
]

export function pickAnchor() {
  return 'The canary lives in ' + ARTIFACT_POOL[crypto.randomBytes(1)[0] % ARTIFACT_POOL.length] +
    '. Include 2-4 OTHER conventionally-exposed platform artifacts as decoys (no canary).'
}
