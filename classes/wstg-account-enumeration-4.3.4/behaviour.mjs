// WSTG-IDNT-04 (4.3.4) — Account Enumeration behaviour.
//
// Login endpoint with three response branches:
//   - GET → render the login form
//   - POST with privileged-username + ANY password → "Wrong password for
//     <username>" (the differential vector — the response echoes the
//     username back, and the privileged username's structure contains
//     the canary, so the response body carries the canary)
//   - POST with any decoy username → "No such account" generic
//
// The bug is the differential AND the predictable-structure leak: the
// privileged username's name itself reveals the canary. A defended app
// would respond identically for both branches ("Credentials submitted
// are not valid") and use opaque IDs (UUIDs) rather than meaningful
// patterns.

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-IDNT-04',
  class: 'Account Enumeration',
  defenceTiers: [0],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path),

  matchesRequest({ reqUrl, scenario }) {
    return reqUrl.pathname === scenario.endpoint.path
  },

  async handleRequest({ req, scenario, helpers, renderPage, manifest }) {
    const username = await readUsername(req, helpers)
    if (req.method === 'GET' && username == null) {
      return { status: 200, body: renderPage(scenario.body.replace('{FORM}', renderForm(scenario))) }
    }
    const submitted = String(username || '').trim()
    if (!submitted) {
      return { status: 400, body: renderPage(scenario.body.replace('{FORM}', renderForm(scenario, 'Please enter a username.'))) }
    }
    // VULN — branch on whether the username matches a real account, and
    // echo it back. A defended app would respond identically for valid +
    // invalid + omit the username from the response entirely.
    const privileged = scenario.privilegedUsername.replaceAll('{CANARY}', manifest.perDeployCanary)
    if (submitted === privileged) {
      return { status: 401, body: renderPage(scenario.body.replace('{FORM}', renderForm(scenario, `Wrong password for ${escapeHtml(submitted)}. Please try again.`))) }
    }
    return { status: 401, body: renderPage(scenario.body.replace('{FORM}', renderForm(scenario, 'No such account. Check your username and try again.'))) }
  },

  // Validator: submit a login attempt with the privileged username +
  // any password. The differential response body carries the username
  // (containing the canary) verbatim. The canonical payload (built in
  // defences.mjs) already has the canary substituted into the username.
  async fireExploit({ baseUrl, scenario, payload }) {
    const body = `username=${encodeURIComponent(payload)}&password=anything`
    const r = await fetch(`${baseUrl}${scenario.endpoint.path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    })
    return { status: r.status, body: await r.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

async function readUsername(req, helpers) {
  if (req.method === 'GET') {
    const url = new URL(req.url, 'http://x')
    return url.searchParams.get('username')
  }
  if (req.method === 'POST') {
    const form = new URLSearchParams(helpers.rawBody || '')
    return form.get('username')
  }
  return null
}

function renderForm(scenario, errorMsg = '') {
  const err = errorMsg ? `<p class="login-error" role="alert" style="color:#b00;margin:0 0 12px;font-size:13px">${escapeHtml(errorMsg)}</p>` : ''
  return `<form method="POST" action="${escapeAttr(scenario.endpoint.path)}" style="display:flex;flex-direction:column;gap:12px;max-width:380px">
    ${err}
    <label style="display:flex;flex-direction:column;gap:4px">
      <span style="font-size:13px">Username</span>
      <input type="text" name="username" autocomplete="username" required style="padding:9px 12px;border:1px solid #c8c8c8;border-radius:6px;font-size:14px">
    </label>
    <label style="display:flex;flex-direction:column;gap:4px">
      <span style="font-size:13px">Password</span>
      <input type="password" name="password" required placeholder="${escapeAttr(scenario.validPasswordPlaceholder)}" style="padding:9px 12px;border:1px solid #c8c8c8;border-radius:6px;font-size:14px">
    </label>
    <button type="submit" style="padding:10px 14px;background:#1c1917;color:white;border:none;border-radius:6px;font-size:14px;cursor:pointer">Sign in</button>
  </form>`
}
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
function escapeAttr(s) { return escapeHtml(s).replace(/"/g, '&quot;') }
