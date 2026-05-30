// Per-deploy anchor for LFI (4.7.11.1) — pins the include-parameter name to
// one of the conventionally-attempted names. WSTG-INPV-11 is enumerable by
// attackers against a known pool of common include-param names; we draw from
// that pool per deploy so deploys spread across the real attack surface
// rather than clustering on whichever name happens to be listed first in the
// scenario description (previously every roll picked "section").

import crypto from 'node:crypto'

// Conventional include-parameter names real attackers fuzz against. Each
// represents a different real-world ops convention — short names common in
// PHP-era apps (p, pg, tpl), the explicit ones (page, view, template,
// include, file), the routing-style ones (route, partial, layout), and the
// modularity-style ones (mod, module, fragment).
export const PAGE_PARAM_NAMES = [
  'page', 'p', 'pg',
  'view', 'template', 'tpl',
  'include', 'file', 'section', 'content',
  'doc', 'document',
  'route', 'partial', 'fragment', 'layout',
  'mod', 'module',
]

export function pickAnchor() {
  const idx = crypto.randomBytes(2).readUInt16BE(0) % PAGE_PARAM_NAMES.length
  const name = PAGE_PARAM_NAMES[idx]
  return {
    pageParam: name,
    note: `Set scenario.pageParam to "${name}" verbatim. Do not substitute.`,
  }
}
