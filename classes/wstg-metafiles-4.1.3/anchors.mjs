// Per-deploy anchor for metafile leakage — picks WHICH metafile advertises the
// paths, so deploys spread across all four vectors instead of clustering on
// robots.txt (the model's prior).

import crypto from 'node:crypto'

export const VECTOR_POOL = [
  'leakageVector = robots-disallow — paths listed as Disallow entries in /robots.txt (the classic misconfig: Disallow advertises exactly what to look at)',
  'leakageVector = robots-allow — paths listed as Allow entries under a blanket Disallow in /robots.txt',
  'leakageVector = sitemap-xml — paths listed as <loc> entries in /sitemap.xml',
  'leakageVector = wellknown-security-txt — internal paths referenced in /.well-known/security.txt',
]

export function pickAnchor() {
  return VECTOR_POOL[crypto.randomBytes(1)[0] % VECTOR_POOL.length]
}
