// Per-deploy anchor for backup / unreferenced file exposure (4.2.4) — fixes
// which conventionally-named backup artifact carries the canary.

import crypto from 'node:crypto'

export const BACKUP_POOL = [
  'a full-site archive at a guessable name (backup.zip, www.tar.gz, site.zip)',
  'a database dump at a guessable name (db.sql, dump.sql, database.sql, backup.sql)',
  'a dated backup archive (backup-2024.tar.gz, site-backup-latest.zip)',
  'an unreferenced export file (export.csv, users.csv, data-export.json)',
  'a release/deploy artifact left behind (release.tar.gz, build.zip, dist.zip)',
  'a config/secrets backup (config.bak.zip, secrets-backup.tar)',
  'an old admin export (orders-export.xlsx-as-text, customers.sql)',
]

export function pickAnchor() {
  return 'The canary lives in ' + BACKUP_POOL[crypto.randomBytes(1)[0] % BACKUP_POOL.length] +
    '. Since binary archives can not be rendered, represent the canary-bearing file as a TEXT listing or extract of its contents (a SQL dump excerpt, a CSV, a file index) with pr_<canary> as a natural value inside. Include 2-4 other guessable backup/unreferenced filenames as decoys.'
}
