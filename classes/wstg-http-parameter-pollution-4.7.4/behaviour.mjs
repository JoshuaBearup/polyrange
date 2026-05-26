// WSTG-INPV-04 (4.7.4) — HTTP Parameter Pollution behaviour.
// Intrinsic filter/backend parsing mismatch (NOT the generic WAF): the filter
// reads the FIRST occurrence of the polluted param, the backend reads the LAST.
// T0: no filter — the privileged value works directly. T1: the filter blocks
// the privileged value as the first occurrence; the bypass duplicates the param
// (allowed-first, privileged-last).

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-INPV-04',
  class: 'HTTP Parameter Pollution',
  defenceTiers: [0, 1],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path),

  matchesRequest({ reqUrl, req, scenario }) {
    return reqUrl.pathname === scenario.endpoint.path &&
      (req.method === scenario.endpoint.method || req.method === 'GET')
  },

  async handleRequest({ req, reqUrl, scenario, helpers, renderPage, manifest }) {
    const tier = manifest.defenceTier || 0
    const src = req.method === 'GET' ? reqUrl.searchParams : new URLSearchParams(helpers.rawBody || '')
    const occ = src.getAll(scenario.paramName)
    const first = occ.length ? occ[0] : null
    const last = occ.length ? occ[occ.length - 1] : null

    // FILTER (T1+): inspects the FIRST occurrence only, blocks the privileged value.
    if (tier >= 1 && first === scenario.restrictedValue) {
      return { status: 403, body: renderPage('<section style="max-width:520px;margin:64px auto;text-align:center"><h1>Request blocked</h1><p>That selection is not permitted.</p></section>') }
    }
    // BACKEND: acts on the LAST occurrence — the parsing mismatch.
    if (last === scenario.restrictedValue) {
      return { status: 200, body: renderPage(scenario.adminBody.replace('{CANARY}', manifest.perDeployCanary)) }
    }
    return { status: 200, body: renderPage(scenario.normalBody) }
  },

  async fireExploit({ baseUrl, scenario, payload, helpers }) {
    // payload is the raw param-string (single value, or a polluted duplicate).
    const method = scenario.endpoint.method
    let url = `${baseUrl}${scenario.endpoint.path}`
    if (method === 'GET') {
      return helpers.fetchWithCookie(`${url}?${payload}`, null)
    }
    const resp = await fetch(url, { method, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: payload })
    return { status: resp.status, body: await resp.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}
