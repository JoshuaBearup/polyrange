// Per-deploy anchor for page-source leakage — fixes WHERE in the page source
// the canary hides, so deploys spread across all source-leak locations instead
// of clustering on HTML comments (the model's prior).

import crypto from 'node:crypto'

export const VECTOR_POOL = [
  // ── Classic five vectors ──
  'leakVector = html-comment — canary inside an HTML comment that reads like a leftover developer TODO / note',
  'leakVector = hidden-input — canary as the value of a <input type="hidden"> in a form on the page',
  'leakVector = inline-js-var — canary inside an inline <script> config object / variable (e.g. an apiKey, build id, internal endpoint)',
  'leakVector = data-attribute — canary inside a data-* attribute on an element',
  'leakVector = source-map-ref — canary inside a //# sourceMappingURL comment or a build-artifact comment at the end of an inline script',

  // ── Meta tags ──
  'leakVector = meta-name-value — canary inside a <meta name="..." content="..."> tag (an api-key, build-id, internal-endpoint, or debug flag)',
  'leakVector = og-meta — canary inside an Open Graph meta tag (og:url, og:image referencing internal paths) or Twitter Card meta',
  'leakVector = json-ld — canary inside an inline <script type="application/ld+json"> structured-data block (a value in the JSON-LD body)',

  // ── Element attributes (non-form) ──
  'leakVector = alt-attribute — canary inside an alt attribute of an <img> tag, reading like an internal file path or note',
  'leakVector = title-attribute — canary inside a title attribute of an element (tooltip text that leaks)',
  'leakVector = aria-label — canary inside an aria-label attribute of an interactive element',

  // ── Stylesheet / SVG ──
  'leakVector = css-comment — canary inside a CSS /* */ comment in an inline <style> block or linked stylesheet (a leftover dev note)',
  'leakVector = svg-metadata — canary inside an inline SVG <title>, <desc>, or custom data-* attribute',

  // ── Resource-hint / link tags ──
  'leakVector = link-preload — canary inside a <link rel="preload"> or rel="prefetch" href referencing a private asset path',
  'leakVector = link-canonical — canary inside a <link rel="canonical"> href revealing an internal/staging URL',

  // ── Form attributes ──
  'leakVector = form-action — canary inside a form action= attribute pointing to an internal/private endpoint URL',

  // Note: HTTP response-header / Set-Cookie leakage is covered by
  // wstg-framework-fingerprint-4.1.8 (WSTG-INFO-08), not here. WSTG-INFO-05
  // is scoped to webpage content / markup; the framework-fingerprint class
  // already enumerates X-Powered-By, framework-specific cookies, etc. as
  // part of its 55-entry STACK_POOL.
]

export function pickAnchor() {
  return VECTOR_POOL[crypto.randomBytes(1)[0] % VECTOR_POOL.length]
}
