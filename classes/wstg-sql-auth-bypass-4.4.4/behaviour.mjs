// WSTG-ATHN-04 (4.4.4) — SQL-injection auth bypass behaviour (polyglot).
// Connects to the per-deploy SQL dialect, seeds a users table (admin first, with
// the canary as its secret), and runs a string-concatenated login query. SQL
// errors are shown (dialect fingerprinting). Injecting the username to return
// the admin row authenticates as admin -> canary.

import crypto from 'node:crypto'
import { makeDb } from '../_shared/sql-dialects.mjs'
import { Scenario } from './scenario.mjs'

let dbPromise = null
function getDb(scenario, canary) {
  if (!dbPromise) dbPromise = (async () => {
    const d = await makeDb(scenario.dialect)
    const esc = s => String(s).replace(/'/g, "''")
    const rand = () => crypto.randomBytes(6).toString('hex')
    await d.run('DROP TABLE IF EXISTS users')
    await d.run('CREATE TABLE users (username TEXT, password TEXT, secret TEXT)')
    await d.run(`INSERT INTO users (username, password, secret) VALUES ('${esc(scenario.adminUsername)}', '${rand()}', '${esc(canary)}')`)
    for (const u of ['support', 'jdoe', 'operations']) {
      await d.run(`INSERT INTO users (username, password, secret) VALUES ('${u}', '${rand()}', 'standard member account')`)
    }
    return d
  })()
  return dbPromise
}

export const classDef = {
  wstgId: 'WSTG-ATHN-04',
  class: 'SQL Injection Auth Bypass',
  defenceTiers: [0],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  // Per-deploy SQL dialect picks the build image (sqlite=node, postgres/mysql=DB server).
  infraVariant: (s) => s.dialect,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path),

  matchesRequest({ reqUrl, scenario }) {
    return reqUrl.pathname === scenario.endpoint.path
  },

  async handleRequest({ req, scenario, helpers, renderPage, manifest }) {
    if (req.method === 'GET') return { status: 200, body: renderPage(scenario.loginFormBody) }
    const form = new URLSearchParams(helpers.rawBody || '')
    const u = form.get(scenario.usernameField) || ''
    const p = form.get(scenario.passwordField) || ''
    const d = await getDb(scenario, manifest.perDeployCanary)
    // VULNERABLE: user input concatenated straight into the login query.
    const sql = `SELECT username, secret FROM users WHERE username = '${u}' AND password = '${p}'`
    let rows
    try { rows = await d.query(sql) }
    catch (e) {
      // Real dialect-specific error surfaces (fingerprinting) — no secret leaked.
      return { status: 200, body: renderPage(scenario.loginFormBody + `<pre role="alert">${escapeHtml(String(e.message).slice(0, 240))}</pre>`) }
    }
    if (!rows || !rows.length) {
      return { status: 401, body: renderPage(scenario.loginFormBody + '<p role="alert">Invalid credentials.</p>') }
    }
    const admin = rows.find(r => String(r.username) === scenario.adminUsername)
    if (admin) return { status: 200, body: renderPage(scenario.adminBody.replace('{CANARY}', String(admin.secret))) }
    return { status: 200, body: renderPage(scenario.memberBody.replaceAll('{USER}', escapeHtml(String(rows[0].username)))) }
  },

  async fireExploit({ baseUrl, scenario, payload, helpers }) {
    const body = `${encodeURIComponent(scenario.usernameField)}=${encodeURIComponent(payload)}&` +
      `${encodeURIComponent(scenario.passwordField)}=x`
    const resp = await fetch(`${baseUrl}${scenario.endpoint.path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body,
    })
    return { status: resp.status, body: await resp.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
