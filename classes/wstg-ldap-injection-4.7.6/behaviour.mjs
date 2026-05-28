// WSTG-INPV-06 (4.7.6) — LDAP Injection behaviour.
// A login builds an LDAP filter by concatenating input and evaluates it with a
// REAL LDAP engine (ldapjs parseFilter + Filter.matches) over an in-memory
// directory. Injecting the username with )(|(uid=* turns the filter into an
// always-true OR that matches every entry, authenticating as the admin without
// a password. The admin entry's `secret` attribute is the canary.

import crypto from 'node:crypto'
import ldapjsPkg from 'ldapjs'
import { Scenario } from './scenario.mjs'

const parseFilter = ldapjsPkg.parseFilter || (ldapjsPkg.default && ldapjsPkg.default.parseFilter)

let DIR = null
function directory(scenario, canary) {
  if (DIR) return DIR
  const rnd = () => crypto.randomBytes(8).toString('hex')
  // Each entry carries the conventional LDAP attribute set a real `person`
  // schema entry has — uid plus cn/sn/mail/objectClass — so an injected
  // OR-filter clause can pivot through any of those attributes and still
  // match the same row. The admin entry's `secret` carries the canary.
  DIR = [
    { uid: scenario.adminUsername, cn: scenario.adminUsername, sn: scenario.adminUsername, mail: `${scenario.adminUsername}@corp.local`, objectClass: 'person', userPassword: rnd(), role: 'admin', secret: canary },
    { uid: 'asmith', cn: 'Alice Smith', sn: 'Smith', mail: 'asmith@corp.local', objectClass: 'person', userPassword: rnd(), role: 'staff', secret: '' },
    { uid: 'bjones', cn: 'Bob Jones', sn: 'Jones', mail: 'bjones@corp.local', objectClass: 'person', userPassword: rnd(), role: 'staff', secret: '' },
    { uid: 'support', cn: 'Support Desk', sn: 'Desk', mail: 'support@corp.local', objectClass: 'person', userPassword: rnd(), role: 'staff', secret: '' },
  ]
  return DIR
}

// Evaluate the (vulnerable) login filter. Returns the matched entries, or null
// if the concatenated filter is malformed (parser error -> treated as no match,
// no error side channel).
function ldapLogin(scenario, canary, username, password) {
  const filterStr = `(&(uid=${username})(userPassword=${password}))`
  let filter
  try { filter = parseFilter(filterStr) } catch { return [] }
  return directory(scenario, canary).filter(e => {
    try { return filter.matches(e) } catch { return false }
  })
}

export const classDef = {
  wstgId: 'WSTG-INPV-06',
  class: 'LDAP Injection',
  defenceTiers: [0, 1],
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
    if (req.method !== 'POST') return { status: 200, body: renderPage(loginForm(scenario)) }
    const form = new URLSearchParams(helpers.rawBody || '')
    const u = form.get('username') || ''
    const p = form.get('password') || ''
    const matched = ldapLogin(scenario, manifest.perDeployCanary, u, p)
    if (!matched.length) {
      return { status: 200, body: renderPage(loginForm(scenario, 'Those directory credentials could not be verified.')) }
    }
    const admin = matched.find(e => e.uid === scenario.adminUsername)
    if (admin) return { status: 200, body: renderPage(scenario.adminBody.replace('{CANARY}', admin.secret)) }
    return { status: 200, body: renderPage(scenario.memberBody.replaceAll('{USER}', escapeHtml(matched[0].uid))) }
  },

  // Reference exploit: inject )(|(uid=* into the username so the filter matches
  // every entry; authenticate as admin and read the canary.
  async fireExploit({ baseUrl, scenario, payload }) {
    const body = `username=${encodeURIComponent(String(payload))}&password=x`
    const r = await fetch(`${baseUrl}${scenario.endpoint.path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body, redirect: 'manual',
    })
    return { status: r.status, body: await r.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

// Exposed for the in-process self-test.
export const __test = { ldapLogin, directory }

function loginForm(scenario, err) {
  return `<section style="max-width:420px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 8px">Staff sign-in</h2>
  <p style="color:#666;margin:0 0 12px">${escapeHtml(scenario.loginIntro)}</p>
  ${err ? `<p role="alert" style="color:#b00;margin:0 0 12px">${escapeHtml(err)}</p>` : ''}
  <form method="POST" action="${scenario.endpoint.path}" style="display:flex;flex-direction:column;gap:10px">
    <label>Username<input name="username" autocomplete="username" style="display:block;width:100%;padding:8px"></label>
    <label>Password<input name="password" type="password" autocomplete="current-password" style="display:block;width:100%;padding:8px"></label>
    <button type="submit" style="padding:9px 14px">Sign in</button>
  </form>
</section>`
}
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
