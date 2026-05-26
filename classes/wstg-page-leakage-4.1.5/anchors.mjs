// Per-deploy anchor for page-source leakage — fixes WHERE in the source the
// canary hides, so deploys spread across all source-leak locations instead of
// clustering on HTML comments.

import crypto from 'node:crypto'

export const VECTOR_POOL = [
  'leakVector = html-comment — canary inside an HTML comment that reads like a leftover developer TODO / note',
  'leakVector = hidden-input — canary as the value of a <input type="hidden"> in a form on the page',
  'leakVector = inline-js-var — canary inside an inline <script> config object / variable (e.g. an apiKey, build id, internal endpoint)',
  'leakVector = data-attribute — canary inside a data-* attribute on an element',
  'leakVector = source-map-ref — canary inside a //# sourceMappingURL comment or a build-artifact comment at the end of an inline script',
]

export function pickAnchor() {
  return VECTOR_POOL[crypto.randomBytes(1)[0] % VECTOR_POOL.length]
}
