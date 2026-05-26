// WSTG-INPV-05.4 — PostgreSQL SQL Injection behaviour.
// Backed by real Postgres. The legitimate query concatenates user input
// into a WHERE clause (no parameterisation) — vulnerable to UNION-based
// injection that pulls from a sensitive table sharing the same shape.

import crypto from 'node:crypto'
import { Scenario } from './scenario.mjs'
import { bulkInsertRecords } from '../_shared/synthesize-records.mjs'

const ROW_SHAPE = `(id TEXT PRIMARY KEY, owner_session TEXT NOT NULL, data JSONB NOT NULL)`

export const classDef = {
  wstgId: 'WSTG-INPV-05.4',
  class: 'SQLi',
  defenceTiers: [0, 1, 2, 3, 4],
  Scenario,
  requiresDatabase: true,
  supportsSignup: true,
  needsSignup: true,

  // ============================================================
  // Schema + signup hooks
  // ============================================================
  async initSchema({ db, rawScenario }) {
    const scenario = Scenario.parse(rawScenario)
    const p = scenario.primaryTable
    const s = scenario.sensitiveTable
    if (p === s) throw new Error('primaryTable and sensitiveTable must differ')

    await db.query(`DROP TABLE IF EXISTS ${quoteIdent(p)}`)
    await db.query(`DROP TABLE IF EXISTS ${quoteIdent(s)}`)
    await db.query(`CREATE TABLE ${quoteIdent(p)} ${ROW_SHAPE}`)
    await db.query(`CREATE TABLE ${quoteIdent(s)} ${ROW_SHAPE}`)

    // primaryTableRows / sensitiveTableRows are synthesized by the deploy
    // pipeline (arrays of field-objects). Wrap each into the (id, owner, data)
    // shape and bulk-insert.
    const primaryRecords = (scenario.primaryTableRows || []).map((fields, i) => ({
      identifier: `r_${i}_${crypto.randomBytes(2).toString('hex')}`,
      ownerSessionId: 'sess_legacy',
      fields,
    }))
    const sensitiveRecords = (scenario.sensitiveTableRows || []).map((fields, i) => ({
      identifier: `s_${i}_${crypto.randomBytes(2).toString('hex')}`,
      ownerSessionId: 'sess_internal',
      fields,
    }))
    await bulkInsertRecords(db, quoteIdent(p), primaryRecords)
    await bulkInsertRecords(db, quoteIdent(s), sensitiveRecords)
  },

  async onSignup({ db, sessionId, rawScenario, signupData }) {
    const scenario = Scenario.parse(rawScenario)
    const p = scenario.primaryTable
    const fields = {}
    for (const [k, v] of Object.entries(scenario.signupRecordTemplate)) {
      fields[k] = String(v).replace(/\{email\}/g, signupData.email || '')
    }
    const newId = 'u_' + crypto.randomBytes(5).toString('hex')
    await db.query(
      `INSERT INTO ${quoteIdent(p)} (id, owner_session, data) VALUES ($1, $2, $3)`,
      [newId, sessionId, JSON.stringify(fields)]
    )
    // Redirect handled by runtime from scenario.postSignupLandingPath
    return { recordIdentifier: newId }
  },

  // ============================================================
  // Runtime: request matching + handling
  // ============================================================
  matchesRequest({ reqUrl, req, scenario }) {
    if (req.method !== (scenario.endpoint.method || 'GET')) return false
    return reqUrl.pathname === scenario.endpoint.path
  },

  async handleRequest({ req, reqUrl, scenario, session, db, helpers, renderPage }) {
    const rawInput = await helpers.extractInput(req, reqUrl, scenario.slots.user_input)

    // Empty query — real e-commerce UX: prompt user, don't dump records.
    if (!rawInput || rawInput.trim() === '') {
      return {
        status: 200,
        body: renderPage(scenario.body.replace('{RESULTS}', '<p class="search-prompt" style="color:#666;font-style:italic;padding:24px 0">Enter a term above to begin browsing.</p>')),
      }
    }

    const p = scenario.primaryTable
    const sess = (session || 'anon').replace(/'/g, "''")
    // VULNERABLE: rawInput interpolated, not parameterised.
    const sql = `SELECT id, owner_session, data FROM ${quoteIdent(p)} WHERE owner_session = '${sess}' AND data::text ILIKE '%${rawInput}%'`

    try {
      const result = await db.query(sql)
      const rendered = renderRows(result.rows)
      return { status: 200, body: renderPage(scenario.body.replace('{RESULTS}', rendered)) }
    } catch (err) {
      const errBody = `<pre class="db-error">Database error: ${escapeHtml(err.message)}</pre>`
      return { status: 200, body: renderPage(scenario.body.replace('{RESULTS}', errBody)) }
    }
  },

  // ============================================================
  // Deploy validator: fire a payload through the search endpoint
  // ============================================================
  async fireExploit({ scenario, payload, sessionCookie, helpers }) {
    // Honours scenario.endpoint.method + scenario.slots.user_input.location
    return helpers.fireScenarioRequest({ scenario, payload, sessionCookie })
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) => {
    return responseBody.includes(perDeployCanary)
  },
}

// ============================================================
// Helpers
// ============================================================
// Render rows as themed cards based on the data JSONB blob. Drops internal
// columns (id, owner_session) which a real search UI would not surface.
// UNION-bypass rows from the sensitive table share the same row shape and
// render the same way — their data blob (containing the canary) appears
// inline in the cards.
function renderRows(rows) {
  if (!rows.length) return '<p class="no-results" style="color:#666;padding:24px 0">No matching results.</p>'
  return '<div class="results-grid" style="display:grid;gap:12px;padding:16px 0">' +
    rows.map(r => {
      const data = (typeof r.data === 'object' && r.data) ? r.data : {}
      const fields = Object.entries(data).map(([k, v]) =>
        `<div style="font-size:14px;margin:4px 0"><span style="color:#666;text-transform:capitalize">${escapeHtml(k.replace(/_/g, ' '))}:</span> <span>${escapeHtml(stringify(v))}</span></div>`
      ).join('')
      return `<article class="result-card" style="border:1px solid #e5e5e5;border-radius:8px;padding:16px;background:#fafafa">${fields}</article>`
    }).join('') +
  '</div>'
}

function stringify(v) {
  if (v === null || v === undefined) return ''
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

function quoteIdent(name) {
  if (!/^[a-z][a-z0-9_]*$/.test(name)) {
    throw new Error(`Invalid table name: ${name}`)
  }
  return '"' + name + '"'
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
