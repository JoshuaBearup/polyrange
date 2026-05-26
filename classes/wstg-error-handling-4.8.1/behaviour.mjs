// WSTG-ERRH-01 (4.8.1) — Improper Error Handling behaviour.
// Stateless. The feature parses the input as JSON: valid input → success page;
// malformed input → a verbose debug error page that leaks an internal secret
// (the canary, injected by the runtime on the error path only).

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-ERRH-01',
  class: 'Improper Error Handling',
  defenceTiers: [0],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,                 // canary injected into the error page, not in the scenario JSON
  discoveryMode: 'observation',        // the feature is linked from the surface
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    (typeof s.formBody === 'string' && s.formBody.includes(s.endpoint.path)) ||
    (typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path)),

  matchesRequest({ reqUrl, req, scenario }) {
    if (reqUrl.pathname !== scenario.endpoint.path) return false
    return req.method === scenario.endpoint.method || req.method === 'GET'
  },

  async handleRequest({ req, reqUrl, scenario, helpers, renderPage, manifest }) {
    if (req.method === 'GET') return { status: 200, body: renderPage(scenario.formBody) }
    const input = await helpers.extractInput(req, reqUrl, scenario.slots.user_input)
    try {
      const parsed = JSON.parse(String(input))
      return { status: 200, body: renderPage(scenario.resultBody.replace('{OUTPUT}', escapeHtml(JSON.stringify(parsed)))) }
    } catch (e) {
      // VULNERABLE: unhandled parse error → verbose debug page leaking a secret.
      const trace = scenario.leakedTrace
        .replace('{CANARY}', manifest.perDeployCanary)
        .replace('{ERROR}', escapeHtml(String(e.message)))
      return { status: 500, body: renderPage(trace) }
    }
  },

  async fireExploit({ baseUrl, scenario, payload, helpers }) {
    const slot = scenario.slots.user_input
    const method = scenario.endpoint.method
    let url = `${baseUrl}${scenario.endpoint.path}`
    if (slot.location === 'query' || method === 'GET') {
      url += `?${encodeURIComponent(slot.name)}=${encodeURIComponent(payload)}`
      return helpers.fetchWithCookie(url, null)
    }
    const headers = {}
    let body
    if (slot.location === 'body-json') {
      headers['Content-Type'] = 'application/json'; body = JSON.stringify({ [slot.name]: payload })
    } else {
      headers['Content-Type'] = 'application/x-www-form-urlencoded'
      body = `${encodeURIComponent(slot.name)}=${encodeURIComponent(payload)}`
    }
    const resp = await fetch(url, { method, headers, body })
    return { status: resp.status, body: await resp.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
