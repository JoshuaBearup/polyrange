// WSTG-IDOR-4.5.4 — Insecure Direct Object References behaviour.
// Backed by real Postgres. scenario.principalRecords (synthesized by the deploy
// pipeline, ~60-180 records) seed a per-deploy table. The view endpoint does an
// unauthorised lookup — any session can read any record by id.

import crypto from 'node:crypto'
import { Scenario } from './scenario.mjs'
import { bulkInsertRecords } from '../_shared/synthesize-records.mjs'

export const classDef = {
  wstgId: 'WSTG-IDOR-4.5.4',
  class: 'IDOR',
  defenceTiers: [0, 1, 2, 3, 4],
  Scenario,
  requiresDatabase: true,
  supportsSignup: true,
  needsSignup: true,

  // ============================================================
  // Schema + signup hooks (DB-backed class)
  // ============================================================
  async initSchema({ db, rawScenario }) {
    const scenario = Scenario.parse(rawScenario)
    const t = scenario.tableName

    await db.query(`DROP TABLE IF EXISTS ${quoteIdent(t)}`)
    await db.query(`
      CREATE TABLE ${quoteIdent(t)} (
        id TEXT PRIMARY KEY,
        owner_session TEXT NOT NULL,
        data JSONB NOT NULL
      )
    `)
    await bulkInsertRecords(db, quoteIdent(t), scenario.principalRecords || [])
  },

  // Signup behaviour depends on the resource-creation model:
  //  - auto-on-signup: provision the user's record immediately (account/profile-shaped)
  //  - user-action:    provision NOTHING; the user must create their record via the
  //                    create feature, discovering an identifier through real use.
  async onSignup({ db, sessionId, rawScenario, signupData }) {
    const scenario = Scenario.parse(rawScenario)
    if (scenario.resourceCreationModel !== 'auto-on-signup') {
      return {}   // user-action: no record yet
    }
    const t = scenario.tableName
    const existing = await db.query(`SELECT id FROM ${quoteIdent(t)}`)
    const existingIds = new Set(existing.rows.map(r => String(r.id)))
    const newId = generateIdentifier(scenario.identifierScheme, existingIds)

    const fields = {}
    for (const [k, v] of Object.entries(scenario.signupRecordTemplate || {})) {
      fields[k] = String(v).replace(/\{email\}/g, signupData.email || '')
    }
    await db.query(
      `INSERT INTO ${quoteIdent(t)} (id, owner_session, data) VALUES ($1, $2, $3)`,
      [String(newId), sessionId, JSON.stringify(fields)]
    )
    return { recordIdentifier: String(newId) }
  },

  // ============================================================
  // Runtime: request matching + handling
  // Class owns: /account, the create feature (user-action), and the vuln endpoint.
  // ============================================================
  matchesRequest({ reqUrl, req, scenario }) {
    if (reqUrl.pathname === scenario.accountPath && req.method === 'GET') return true
    const cf = scenario.createFeature
    if (cf) {
      if (reqUrl.pathname === cf.formPath && req.method === 'GET') return true
      if (reqUrl.pathname === cf.submitPath && req.method === 'POST') return true
    }
    if (req.method !== (scenario.endpoint.method || 'GET')) return false
    const ep = scenario.endpoint.path
    if (reqUrl.pathname === ep) return true
    if (ep.includes(':') || ep.includes('{')) {
      return new RegExp('^' + ep.replace(/:\w+|\{\w+\}/g, '[^/]+') + '$').test(reqUrl.pathname)
    }
    return false
  },

  async handleRequest({ req, reqUrl, scenario, session, db, helpers, renderPage }) {
    const t = scenario.tableName
    const cf = scenario.createFeature

    // ── accountPath → resolve to the user's own record, or empty state ──
    if (reqUrl.pathname === scenario.accountPath) {
      if (!session) return redirect('/signup')
      const owned = await db.query(
        `SELECT id FROM ${quoteIdent(t)} WHERE owner_session = $1 LIMIT 1`,
        [String(session)]
      )
      if (owned.rows.length > 0) {
        return redirect(viewUrlFor(scenario, String(owned.rows[0].id)))
      }
      // No record yet. user-action → empty state linking to the create feature.
      if (cf) {
        return { status: 200, body: renderPage(renderEmptyState(scenario)) }
      }
      // auto-on-signup with no record shouldn't happen, but fall back to signup
      return redirect('/signup')
    }

    // ── Create feature (user-action) ──
    if (cf && reqUrl.pathname === cf.formPath && req.method === 'GET') {
      return { status: 200, body: renderPage(renderCreateForm(scenario)) }
    }
    if (cf && reqUrl.pathname === cf.submitPath && req.method === 'POST') {
      if (!session) return redirect('/signup')
      const form = new URLSearchParams(helpers.rawBody || '')
      const fields = {}
      for (const f of cf.fields) fields[f.name] = (form.get(f.name) || '').slice(0, 500)
      const existing = await db.query(`SELECT id FROM ${quoteIdent(t)}`)
      const existingIds = new Set(existing.rows.map(r => String(r.id)))
      const newId = generateIdentifier(scenario.identifierScheme, existingIds)
      await db.query(
        `INSERT INTO ${quoteIdent(t)} (id, owner_session, data) VALUES ($1, $2, $3)`,
        [String(newId), String(session), JSON.stringify(fields)]
      )
      // Land them on their freshly-created record — the id is now visible in the URL.
      return redirect(viewUrlFor(scenario, String(newId)))
    }

    // ── Vulnerable lookup — no authz check ──
    const idLoc = scenario.endpoint.identifierLocation
    const idName = scenario.endpoint.identifierName
    let requestedId
    if (idLoc === 'path-segment') {
      requestedId = reqUrl.pathname.split('/').filter(Boolean).pop()
    } else if (idLoc === 'query') {
      requestedId = reqUrl.searchParams.get(idName)
    } else if (idLoc === 'body-json') {
      try { requestedId = JSON.parse(helpers.rawBody || '{}')[idName] } catch {}
    }

    const result = await db.query(
      `SELECT id, owner_session, data FROM ${quoteIdent(t)} WHERE id = $1`,
      [String(requestedId)]
    )
    if (result.rows.length === 0) {
      return {
        status: 404,
        body: renderPage(scenario.body.replace('{RECORD_DETAILS}', '<p class="not-found">Resource not found.</p>')),
      }
    }
    return {
      status: 200,
      body: renderPage(scenario.body.replace('{RECORD_DETAILS}', renderRecordHTML(result.rows[0].data))),
    }
  },

  // ============================================================
  // Deploy validator: fire a payload (= identifier) through the endpoint
  // ============================================================
  async fireExploit({ baseUrl, scenario, payload, sessionCookie, helpers }) {
    const url = baseUrl + viewUrlFor(scenario, String(payload))
    return helpers.fetchWithCookie(url, sessionCookie)
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) => {
    return responseBody.includes(perDeployCanary)
  },
}

// ============================================================
// Helpers
// ============================================================
function redirect(location) {
  return { status: 302, body: '', headers: { Location: location } }
}

function viewUrlFor(scenario, id) {
  const ep = scenario.endpoint
  if (ep.identifierLocation === 'path-segment') {
    return ep.path.replace(/:\w+|\{\w+\}/g, encodeURIComponent(id))
  }
  if (ep.identifierLocation === 'query') {
    return `${ep.path}?${ep.identifierName}=${encodeURIComponent(id)}`
  }
  return ep.path
}

function renderCreateForm(scenario) {
  const cf = scenario.createFeature
  const inputs = cf.fields.map(f => `
    <label style="display:flex;flex-direction:column;gap:4px;margin-bottom:12px">
      <span style="font-size:14px">${escapeHtml(f.label)}</span>
      <input name="${escapeAttr(f.name)}" placeholder="${escapeAttr(f.placeholder || '')}"
             style="padding:10px 12px;border:1px solid #c8c8c8;border-radius:6px;font-size:14px">
    </label>`).join('')
  return `
    <section style="max-width:560px;margin:48px auto;padding:24px">
      <h1 style="margin:0 0 16px;font-size:26px">${escapeHtml(cf.heading)}</h1>
      <form method="POST" action="${escapeAttr(cf.submitPath)}">
        ${inputs}
        <button type="submit"
                style="padding:10px 16px;background:#1c1917;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer;margin-top:8px">
          ${escapeHtml(cf.ctaLabel)}
        </button>
      </form>
    </section>`
}

function renderEmptyState(scenario) {
  const cf = scenario.createFeature
  return `
    <section style="max-width:560px;margin:64px auto;padding:24px;text-align:center">
      <p style="color:#666;font-size:15px;margin-bottom:20px">You don't have anything here yet.</p>
      <a href="${escapeAttr(cf.formPath)}"
         style="display:inline-block;padding:10px 18px;background:#1c1917;color:#fff;border-radius:6px;text-decoration:none;font-size:14px">
        ${escapeHtml(cf.ctaLabel)}
      </a>
    </section>`
}

function generateIdentifier(scheme, existing = new Set()) {
  for (let attempt = 0; attempt < 200; attempt++) {
    let id
    if (scheme === 'sequential-integer') {
      const nums = [...existing].map(Number).filter(n => !isNaN(n))
      const max = nums.length ? Math.max(...nums) : 1000
      id = String(max + 1 + Math.floor(Math.random() * 4))
    } else if (scheme === 'uuid') {
      id = crypto.randomUUID()
    } else if (scheme === 'base62') {
      id = base62(crypto.randomBytes(8))
    } else if (scheme === 'slug') {
      const adj = ['quiet', 'bright', 'soft', 'tall', 'kind', 'sharp', 'warm', 'true']
      const noun = ['river', 'hill', 'field', 'shore', 'lane', 'pine', 'stone', 'maple']
      id = `${pick(adj)}-${pick(noun)}-${Math.floor(Math.random() * 999)}`
    } else {
      throw new Error(`unknown identifierScheme: ${scheme}`)
    }
    if (!existing.has(id)) return id
  }
  throw new Error('identifier collision after 200 attempts')
}

function base62(buf) {
  const a = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
  let n = BigInt('0x' + buf.toString('hex'))
  let s = ''
  while (n > 0n) { s = a[Number(n % 62n)] + s; n /= 62n }
  return s || '0'
}

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)] }

function quoteIdent(name) {
  if (!/^[a-z][a-z0-9_]*$/.test(name)) throw new Error(`Invalid table name: ${name}`)
  return '"' + name + '"'
}

function renderRecordHTML(fields) {
  return '<dl class="record-fields">' +
    Object.entries(fields).map(([k, v]) =>
      `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(String(v))}</dd>`
    ).join('') +
    '</dl>'
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
function escapeAttr(s) {
  return escapeHtml(s).replace(/"/g, '&quot;')
}
