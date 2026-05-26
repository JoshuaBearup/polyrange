// URL safety sanitizer — guarantees GENERATED VULN CONTENT never references a
// publicly-resolvable domain the model-under-test could be induced to fetch
// (SSRF / pivoting safety).
//
// Every http(s):// domain gets a per-deploy hash spliced into its registrable
// label (vermillionsystems.com → vermillionsystems-a1b2c3d4.com): realistic
// TLD preserved, but the domain cannot plausibly have been registered. Public
// IPs collapse to loopback. Already-private IPs / localhost are left alone
// (they're already non-routable, and SSRF targets rely on them).
//
// NOTE: callers run this over scenario / decoys / 404 — NOT over the chrome,
// which carries the real font/CSS/JS CDN links the pages need to render.

function isAlreadySafeHost(host) {
  host = host.toLowerCase()
  if (host === 'localhost') return true
  if (/^127\.\d+\.\d+\.\d+$/.test(host)) return true
  if (/^10\.\d+\.\d+\.\d+$/.test(host)) return true
  if (/^192\.168\.\d+\.\d+$/.test(host)) return true
  if (/^169\.254\.\d+\.\d+$/.test(host)) return true
  if (/^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/.test(host)) return true
  return false
}

// Splice the per-deploy hash into the registrable label (the label before the
// public suffix). Keeps subdomain + TLD; makes the domain unregisterable.
function rewriteHost(host, salt) {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return '127.0.0.1'   // public IP → loopback
  const parts = host.split('.')
  if (parts.length < 2) return `${host}-${salt}`
  const sldIdx = parts.length - 2
  if (!parts[sldIdx].endsWith(`-${salt}`)) parts[sldIdx] = `${parts[sldIdx]}-${salt}`
  return parts.join('.')
}

const URL_RE = /(https?:\/\/)([a-zA-Z0-9.-]+)(?=[/:?#"'\s)\\]|$)/g

export function sanitizeUrlsInText(text, salt) {
  if (typeof text !== 'string') return text
  return text.replace(URL_RE, (m, scheme, host) =>
    isAlreadySafeHost(host) ? m : scheme + rewriteHost(host, salt)
  )
}

export function sanitizeDeep(value, salt) {
  if (typeof value === 'string') return sanitizeUrlsInText(value, salt)
  if (Array.isArray(value)) return value.map(v => sanitizeDeep(v, salt))
  if (value && typeof value === 'object') {
    const out = {}
    for (const [k, v] of Object.entries(value)) out[k] = sanitizeDeep(v, salt)
    return out
  }
  return value
}
