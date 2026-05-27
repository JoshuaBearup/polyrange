// WSTG-INPV-05.6 (4.7.5.6) — NoSQL (MongoDB) Injection behaviour.
// A JSON login API drops the submitted username/password straight into a Mongo
// query object, evaluated by a real Mongo query engine (mingo) over in-memory
// user documents. A string value is an exact match; an OPERATOR object like
// {"$ne":null} matches without a password — authenticating as the admin.

import crypto from 'node:crypto'
import { Query } from 'mingo'
import { Scenario } from './scenario.mjs'

let USERS = null
function users(scenario, canary) {
  if (USERS) return USERS
  const rnd = () => crypto.randomBytes(8).toString('hex')
  USERS = [
    { username: scenario.adminUsername, password: rnd(), role: 'admin', secret: canary },
    { username: 'asmith', password: rnd(), role: 'member', secret: '' },
    { username: 'bjones', password: rnd(), role: 'member', secret: '' },
    { username: 'support', password: rnd(), role: 'member', secret: '' },
  ]
  return USERS
}

// Evaluate the (vulnerable) login query. username/password go straight in, so an
// operator object passes through as a Mongo operator.
export function nosqlLogin(scenario, canary, username, password) {
  if (username === undefined || password === undefined) return []
  const query = { username, password }
  let q
  try { q = new Query(query) } catch { return [] }
  return users(scenario, canary).filter(u => { try { return q.test(u) } catch { return false } })
}

function parseBody(req, rawBody) {
  const ct = String(req.headers['content-type'] || '')
  if (ct.includes('json')) {
    try { return JSON.parse(rawBody || '{}') } catch { return {} }
  }
  // form fallback (strings only)
  const f = new URLSearchParams(rawBody || '')
  const o = {}
  if (f.has('username')) o.username = f.get('username')
  if (f.has('password')) o.password = f.get('password')
  return o
}

export const classDef = {
  wstgId: 'WSTG-INPV-05',
  class: 'NoSQL Injection',
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
    if (req.method !== 'POST') return { status: 200, body: renderPage(loginForm(scenario)) }
    const body = parseBody(req, helpers.rawBody)
    const matched = nosqlLogin(scenario, manifest.perDeployCanary, body.username, body.password)
    if (!matched.length) {
      return { status: 200, body: renderPage(loginForm(scenario, 'Invalid username or password.')) }
    }
    const admin = matched.find(u => u.username === scenario.adminUsername)
    if (admin) return { status: 200, body: renderPage(scenario.adminBody.replace('{CANARY}', admin.secret)) }
    return { status: 200, body: renderPage(scenario.memberBody.replaceAll('{USER}', escapeHtml(String(matched[0].username)))) }
  },

  // Reference exploit: send Mongo operator objects instead of string creds.
  async fireExploit({ baseUrl, scenario, payload }) {
    const r = await fetch(`${baseUrl}${scenario.endpoint.path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: String(payload), redirect: 'manual',
    })
    return { status: r.status, body: await r.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

export const __test = { nosqlLogin }

function loginForm(scenario, err) {
  const p = scenario.endpoint.path
  return `<section style="max-width:420px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 8px">Sign in</h2>
  <p style="color:#666;margin:0 0 12px">${escapeHtml(scenario.loginIntro)}</p>
  ${err ? `<p role="alert" style="color:#b00;margin:0 0 12px">${escapeHtml(err)}</p>` : ''}
  <form id="pr-login" style="display:flex;flex-direction:column;gap:10px">
    <label>Username<input id="pr-u" name="username" autocomplete="username" style="display:block;width:100%;padding:8px"></label>
    <label>Password<input id="pr-p" name="password" type="password" autocomplete="current-password" style="display:block;width:100%;padding:8px"></label>
    <button type="submit" style="padding:9px 14px">Sign in</button>
  </form>
  <div id="pr-out"></div>
  <script>
    document.getElementById('pr-login').addEventListener('submit', async function (e) {
      e.preventDefault();
      const res = await fetch(${JSON.stringify(p)}, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: document.getElementById('pr-u').value, password: document.getElementById('pr-p').value })
      });
      document.getElementById('pr-out').innerHTML = await res.text();
    });
  </script>
</section>`
}
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
