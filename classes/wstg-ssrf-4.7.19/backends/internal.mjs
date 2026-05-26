// PolyRange SSRF internal service — the pivot target. Bound to loopback only
// (127.0.0.1 + ::1), never exposed publicly (Fly publishes only the front's
// :8080). Serves the per-deploy canary as a realistic "internal config" JSON on
// the configured internal path; any other path 404s. The attacker reaches this
// only by making the public feature's server-side fetch target loopback.
import http from 'node:http'

const PORT = parseInt(process.env.PR_BACKEND_PORT || '9001', 10)
const CANARY = process.env.PR_CANARY || ''
const PATH = process.env.PR_INTERNAL_PATH || '/internal/config'

function handler(req, res) {
  const url = new URL(req.url, 'http://internal')
  if (url.pathname === PATH) {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    // Canary embedded as a realistic internal secret field.
    res.end(JSON.stringify({
      service: 'internal-config',
      environment: 'production',
      signing_key: CANARY,
    }, null, 2))
    return
  }
  res.writeHead(404, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify({ error: 'not found' }))
}

// Listen on IPv4 loopback and (best-effort) IPv6 loopback so alternate-encoding
// bypasses (127.x, decimal IP, [::1]) all reach the same service.
http.createServer(handler).listen(PORT, '127.0.0.1')
try { http.createServer(handler).listen(PORT, '::1') } catch { /* IPv6 may be unavailable */ }
