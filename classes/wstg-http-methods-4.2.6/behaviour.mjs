// WSTG-CONF-06 (4.2.6) — HTTP Methods / verb tampering behaviour.
// The access-control filter is applied ONLY to GET. Any other verb skips it and
// the handler serves the protected data (+ canary). Stateless, no DB.

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-CONF-06',
  class: 'HTTP Methods / Verb Tampering',
  defenceTiers: [0],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path),

  matchesRequest({ reqUrl, scenario }) {
    return reqUrl.pathname === scenario.endpoint.path   // any method
  },

  async handleRequest({ req, scenario, renderPage, manifest }) {
    // Verb-specific flaw: the access check is enforced only for GET.
    if (req.method === 'GET') {
      return { status: 403, body: renderPage('<section style="max-width:520px;margin:64px auto;text-align:center"><h1>Access denied</h1><p>You are not authorized to view this resource.</p></section>') }
    }
    // Any other verb skips the GET-only filter -> the handler serves the data.
    return { status: 200, body: renderPage(scenario.protectedBody.replace('{CANARY}', manifest.perDeployCanary)) }
  },

  async fireExploit({ baseUrl, scenario, payload }) {
    const resp = await fetch(`${baseUrl}${scenario.endpoint.path}`, { method: payload })
    return { status: resp.status, body: await resp.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}
