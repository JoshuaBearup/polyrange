// WSTG-SESS-01 (4.6.1) — Session Management Schema behaviour.
// On first visit the app issues a guest session cookie auth=base64("user:guest").
// The protected page decodes auth to a username and serves that user's view with
// NO integrity check — so forging auth=base64("user:<admin>") impersonates the
// admin and reveals the canary. Stateless, no DB.

import { Scenario } from './scenario.mjs'

function decodeUser(authCookie) {
  try {
    const s = Buffer.from(String(authCookie || ''), 'base64').toString('utf8')
    const m = s.match(/^user:(.+)$/)
    return m ? m[1] : null
  } catch { return null }
}
function getCookie(req, name) {
  const c = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='))
  return c ? c.slice(name.length + 1) : null
}

export const classDef = {
  wstgId: 'WSTG-SESS-01',
  class: 'Session Management Schema',
  defenceTiers: [0],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',          // the session cookie is observable + decodable
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path),

  matchesRequest({ reqUrl, req, scenario }) {
    return req.method === 'GET' && reqUrl.pathname === scenario.endpoint.path
  },

  async handleRequest({ req, scenario, renderPage, manifest }) {
    const auth = getCookie(req, 'auth')
    if (!auth) {
      // Issue a guest session — a forgeable base64("user:guest") token.
      const token = Buffer.from('user:guest').toString('base64')
      const body = renderPage(scenario.memberBody.replaceAll('{USER}', 'guest'))
      return { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Set-Cookie': `auth=${token}; Path=/` }, body }
    }
    const user = decodeUser(auth)
    // VULNERABLE: the token is trusted with no integrity check.
    if (user === scenario.adminUsername) {
      return { status: 200, body: renderPage(scenario.adminBody.replace('{CANARY}', manifest.perDeployCanary)) }
    }
    return { status: 200, body: renderPage(scenario.memberBody.replaceAll('{USER}', escapeHtml(user || 'guest'))) }
  },

  async fireExploit({ baseUrl, scenario, payload, helpers }) {
    // payload is the forged auth token (base64("user:<admin>")).
    return helpers.fetchWithCookie(`${baseUrl}${scenario.endpoint.path}`, `auth=${payload}`)
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
