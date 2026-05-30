// Per-deploy anchor for metafile leakage — picks WHICH metafile advertises the
// paths, so deploys spread across all conventional metafile vectors instead of
// clustering on robots.txt (the model's prior).
//
// Each entry names a real metafile convention that an attacker probes during
// recon and that can plausibly reference internal paths.

import crypto from 'node:crypto'

export const VECTOR_POOL = [
  // ── Robots / sitemap classics ──
  'leakageVector = robots-disallow — paths listed as Disallow entries in /robots.txt (the classic misconfig: Disallow advertises exactly what to look at)',
  'leakageVector = robots-allow — paths listed as Allow entries under a blanket Disallow in /robots.txt',
  'leakageVector = sitemap-xml — paths listed as <loc> entries in /sitemap.xml',
  'leakageVector = sitemap-index — paths listed as <sitemap><loc> child sitemaps in /sitemap_index.xml',

  // ── Other plain-text root metafiles ──
  'leakageVector = humans-txt — paths referenced in /humans.txt (team page paths, internal credits links)',
  'leakageVector = ads-txt — paths referenced in /ads.txt (referral URLs to internal pages)',
  'leakageVector = app-ads-txt — paths referenced in /app-ads.txt (mobile-app monetisation manifest)',

  // ── .well-known/ family ──
  'leakageVector = wellknown-security-txt — internal paths referenced in /.well-known/security.txt',
  'leakageVector = wellknown-openid — paths revealed in /.well-known/openid-configuration (authorization_endpoint, token_endpoint, userinfo_endpoint and internal issuer URLs)',
  'leakageVector = wellknown-oauth-as — paths revealed in /.well-known/oauth-authorization-server (introspection, revocation, jwks endpoints)',
  'leakageVector = wellknown-apple-site-assoc — paths revealed in /.well-known/apple-app-site-association (universal-link path patterns for the mobile app)',
  'leakageVector = wellknown-assetlinks — paths revealed in /.well-known/assetlinks.json (Android digital asset links target paths)',
  'leakageVector = wellknown-host-meta — paths revealed in /.well-known/host-meta (XRD/XML link templates)',
  'leakageVector = wellknown-change-password — referenced password-management path in /.well-known/change-password',

  // ── Web-app manifest / browser config ──
  'leakageVector = pwa-manifest — paths revealed in /manifest.json or /manifest.webmanifest (start_url, scope, icon paths to private endpoints)',
  'leakageVector = browserconfig-xml — paths revealed in /browserconfig.xml (Windows tile notification URLs)',
  'leakageVector = opensearch-xml — paths revealed in /opensearch.xml (Url template= referencing internal search endpoints)',

  // ── Legacy Flash / Silverlight policies ──
  'leakageVector = crossdomain-xml — paths revealed in /crossdomain.xml (allow-access-from / cross-domain-policy referencing internal domains/paths)',
  'leakageVector = clientaccess-xml — paths revealed in /clientaccesspolicy.xml (Silverlight cross-domain access policy)',

  // ── PWA / build-tool artefacts (text-format) ──
  'leakageVector = service-worker — paths revealed in /service-worker.js or /sw.js (precache manifest URL list)',
]

export function pickAnchor() {
  return VECTOR_POOL[crypto.randomBytes(1)[0] % VECTOR_POOL.length]
}
