// Per-deploy anchor for cloud-storage exposure (4.2.11) — fixes the exposure
// style of the open bucket/listing carrying the canary.
import crypto from 'node:crypto'

export const STYLE_POOL = [
  'an open S3-style bucket listing (XML ListBucketResult) enumerating objects, one of which holds the canary',
  'an Apache/nginx-style open directory index (/uploads/, /files/) listing files including a sensitive one',
  'a GCS-style bucket JSON listing exposing object names + a sensitive object',
  'a public blob/container index (Azure-style) listing items including a leaked one',
  'an exposed CDN/asset manifest (a JSON index of uploaded files) referencing a private object',
]

export function pickAnchor() {
  return 'The exposure is ' + STYLE_POOL[crypto.randomBytes(1)[0] % STYLE_POOL.length] +
    '. The listing endpoint enumerates several objects (realistic filenames); the canary is inside the CONTENT of the one sensitive object (served at its listed path), not in the listing itself. Represent that object as text (a config, an export, a note) with pr_<canary> as a natural value. The other listed objects are mundane decoys.'
}
