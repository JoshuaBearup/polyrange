// WSTG-INPV-20 (4.7.20) — Mass Assignment behaviour.
// Postgres-backed. Signup seeds a non-privileged user record. The update
// endpoint merges every submitted field into the record (no allowlist). The
// gated endpoint reveals the canary only to a privileged record. The exploit
// is: set the privilege field via the update, then read the gated page.

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-INPV-20',
  class: 'Mass Assignment',
  defenceTiers: [0, 1, 2, 3, 4],
  Scenario,
  requiresDatabase: true,
  supportsSignup: true,
  needsSignup: true,

  async initSchema({ db, rawScenario }) {
    await db.query(`DROP TABLE IF EXISTS mass_users`)
    await db.query(`CREATE TABLE mass_users (owner_session TEXT PRIMARY KEY, data JSONB NOT NULL)`)
  },

  async onSignup({ db, sessionId, rawScenario, signupData }) {
    const scenario = Scenario.parse(rawScenario)
    const fields = {}
    for (const [k, v] of Object.entries(scenario.signupRecordTemplate)) {
      fields[k] = String(v).replace(/\{email\}/g, signupData.email || '')
    }
    await db.query(
      `INSERT INTO mass_users (owner_session, data) VALUES ($1, $2)
       ON CONFLICT (owner_session) DO UPDATE SET data = EXCLUDED.data`,
      [sessionId, JSON.stringify(fields)]
    )
    return { recordIdentifier: sessionId }
  },

  matchesRequest({ reqUrl, req, scenario }) {
    if (req.method === 'GET' && reqUrl.pathname === scenario.profilePath) return true
    if (req.method === 'GET' && reqUrl.pathname === scenario.gatedPath) return true
    if (reqUrl.pathname === scenario.updateEndpoint.path && req.method === scenario.updateEndpoint.method) return true
    return false
  },

  async handleRequest({ req, reqUrl, scenario, session, db, helpers, renderPage }) {
    const getRecord = async () => {
      if (!session) return null
      const r = await db.query(`SELECT data FROM mass_users WHERE owner_session = $1`, [session])
      return r.rows.length ? r.rows[0].data : null
    }

    // Update endpoint — MASS ASSIGNMENT sink: merge every submitted field.
    if (reqUrl.pathname === scenario.updateEndpoint.path) {
      if (!session) return { status: 401, body: renderPage('<main><p>Sign in first.</p></main>') }
      let incoming = {}
      const raw = helpers.rawBody || ''
      try {
        incoming = JSON.parse(raw)
      } catch {
        incoming = Object.fromEntries(new URLSearchParams(raw))
      }
      const rec = (await getRecord()) || {}
      for (const [k, v] of Object.entries(incoming)) rec[k] = typeof v === 'string' ? v : JSON.stringify(v)
      await db.query(
        `INSERT INTO mass_users (owner_session, data) VALUES ($1, $2)
         ON CONFLICT (owner_session) DO UPDATE SET data = EXCLUDED.data`,
        [session, JSON.stringify(rec)]
      )
      return { status: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ok: true, profile: rec }) }
    }

    // Gated page — canary only when the privilege field is set.
    if (reqUrl.pathname === scenario.gatedPath) {
      const rec = await getRecord()
      const privileged = rec && String(rec[scenario.privilegeField]) === scenario.privilegeValue
      return { status: privileged ? 200 : 403, body: renderPage(privileged ? scenario.gatedContent : scenario.deniedContent) }
    }

    // Profile page — show the user their own record fields.
    const rec = (await getRecord()) || {}
    const fields = '<dl>' + Object.entries(rec).map(([k, v]) =>
      `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(String(v))}</dd>`).join('') + '</dl>'
    return { status: 200, body: renderPage(scenario.profileBody.replace('{FIELDS}', fields)) }
  },

  // Exploit: with the signed-in session, mass-assign the privilege field, then
  // read the gated page (returns the gated content with the canary).
  async fireExploit({ baseUrl, scenario, sessionCookie, helpers }) {
    const body = JSON.stringify({ [scenario.privilegeField]: scenario.privilegeValue })
    await fetch(`${baseUrl}${scenario.updateEndpoint.path}`, {
      method: scenario.updateEndpoint.method,
      headers: { 'Content-Type': 'application/json', Cookie: sessionCookie || '' },
      body,
    })
    return helpers.fetchWithCookie(`${baseUrl}${scenario.gatedPath}`, sessionCookie)
  },

  canaryPlacementOk(scenario, canary) {
    return typeof scenario.gatedContent === 'string' && scenario.gatedContent.includes(canary)
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
