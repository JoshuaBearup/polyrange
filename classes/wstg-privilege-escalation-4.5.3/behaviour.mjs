// WSTG-ATHZ-03 (4.5.3) — Privilege Escalation behaviour.
// Session-based (no DB). A logged-in user submits the feature; the server reads
// the role from a CLIENT-SUPPLIED field and trusts it. Normal value → ordinary
// view; tampered to the privileged value → the canary. The escalation is
// forging that field.

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-ATHZ-03',
  class: 'Privilege Escalation',
  defenceTiers: [0],
  Scenario,
  supportsSignup: true,
  needsSignup: true,                   // a logged-in normal user escalates
  canaryRuntime: true,                 // canary injected into the privileged view, not in the scenario JSON
  discoveryMode: 'observation',        // the role field is visible in the feature form
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path),

  matchesRequest({ reqUrl, req, scenario }) {
    if (reqUrl.pathname !== scenario.endpoint.path) return false
    return req.method === scenario.endpoint.method || req.method === 'GET'
  },

  async handleRequest({ req, reqUrl, scenario, session, helpers, renderPage, manifest }) {
    if (!session) {
      return { status: 401, body: renderPage('<section style="max-width:520px;margin:64px auto;text-align:center"><h1>Sign in required</h1></section>') }
    }
    // GET → show the form (with the tamperable hidden role field at normalValue).
    if (req.method === 'GET') {
      return { status: 200, body: renderPage(scenario.formBody) }
    }
    // POST → trust the client-supplied role. Privileged value → privileged data.
    const role = String(await helpers.extractInput(req, reqUrl, scenario.roleSlot) || '')
    if (role === scenario.privilegedValue) {
      return { status: 200, body: renderPage(scenario.adminBody.replace('{CANARY}', manifest.perDeployCanary)) }
    }
    return { status: 200, body: renderPage(scenario.normalBody) }
  },

  async fireExploit({ baseUrl, scenario, payload, sessionCookie, helpers }) {
    // Forge the role to the privileged value, with an ordinary signup session.
    const slot = scenario.roleSlot
    const method = scenario.endpoint.method
    const value = payload || scenario.privilegedValue
    let url = `${baseUrl}${scenario.endpoint.path}`
    const headers = {}
    if (sessionCookie) headers['Cookie'] = sessionCookie
    if (slot.location === 'query' || method === 'GET') {
      url += `?${encodeURIComponent(slot.name)}=${encodeURIComponent(value)}`
      const resp = await fetch(url, { method, headers })
      return { status: resp.status, body: await resp.text() }
    }
    if (slot.location === 'header') {
      headers[slot.name] = value
      const resp = await fetch(url, { method, headers })
      return { status: resp.status, body: await resp.text() }
    }
    let body
    if (slot.location === 'body-json') {
      headers['Content-Type'] = 'application/json'; body = JSON.stringify({ [slot.name]: value })
    } else {
      headers['Content-Type'] = 'application/x-www-form-urlencoded'
      body = `${encodeURIComponent(slot.name)}=${encodeURIComponent(value)}`
    }
    const resp = await fetch(url, { method, headers, body })
    return { status: resp.status, body: await resp.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}
