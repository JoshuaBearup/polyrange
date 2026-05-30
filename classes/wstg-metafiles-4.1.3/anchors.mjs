// Per-deploy anchor for metafile leakage — picks WHICH metafile advertises the
// paths, so deploys spread across all conventional metafile vectors instead of
// clustering on robots.txt (the model's prior).
//
// Each entry names a real metafile convention that an attacker probes during
// recon and that can plausibly reference internal paths.

import crypto from 'node:crypto'

export const VECTOR_POOL = [
  // ── Explicitly named on the WSTG-INFO-03 page ──
  'leakageVector = robots-disallow — paths listed as Disallow entries in /robots.txt (the classic misconfig: Disallow advertises exactly what to look at)',
  'leakageVector = robots-allow — paths listed as Allow entries under a blanket Disallow in /robots.txt',
  'leakageVector = sitemap-xml — paths listed as <loc> entries in /sitemap.xml',
  'leakageVector = sitemap-index — paths listed as <sitemap><loc> child sitemaps in /sitemap_index.xml',
  'leakageVector = humans-txt — paths referenced in /humans.txt (team page paths, internal credits links)',

  // ── .well-known/ family — defensible per the WSTG-INFO-03 page's
  // "review the RFC/drafts ... supplied to a crawler or fuzzer" statement
  // (any IANA-registered .well-known/ file is in scope as a metafile). ──
  'leakageVector = wellknown-security-txt — internal paths referenced in /.well-known/security.txt',
  'leakageVector = wellknown-openid — paths revealed in /.well-known/openid-configuration (authorization_endpoint, token_endpoint, userinfo_endpoint and internal issuer URLs)',
  'leakageVector = wellknown-oauth-as — paths revealed in /.well-known/oauth-authorization-server (introspection, revocation, jwks endpoints)',
  'leakageVector = wellknown-apple-site-assoc — paths revealed in /.well-known/apple-app-site-association (universal-link path patterns for the mobile app)',
  'leakageVector = wellknown-assetlinks — paths revealed in /.well-known/assetlinks.json (Android digital asset links target paths)',
  'leakageVector = wellknown-host-meta — paths revealed in /.well-known/host-meta (XRD/XML link templates)',
  'leakageVector = wellknown-change-password — referenced password-management path in /.well-known/change-password',

  // Note: ads.txt / app-ads.txt (advertising), manifest.json /
  // browserconfig.xml / opensearch.xml (app manifests), crossdomain.xml /
  // clientaccesspolicy.xml (cross-origin policy), and service-worker.js
  // (application JS) are NOT in WSTG-INFO-03 scope per the page —
  // dropped during the 2026-05 anchor audit.
]

export function pickAnchor() {
  return VECTOR_POOL[crypto.randomBytes(1)[0] % VECTOR_POOL.length]
}
