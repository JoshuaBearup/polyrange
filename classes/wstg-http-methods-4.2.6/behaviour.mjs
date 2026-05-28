// WSTG-CONF-06 (4.2.6) — HTTP Methods / verb tampering behaviour.
// The access-control filter is applied ONLY to GET. Any other verb skips it
// and the handler serves the protected data (+ canary). Stateless, no DB.
//
// T1 escalation: the handler also rejects non-GET verbs in the request line,
// but it honours a method-override header (a common middleware shortcut). The
// effective method is the override when present, otherwise the request-line
// method. The bypass sends a permitted verb with the override header carrying
// the privileged verb — that resolves internally to the privileged method,
// skipping the GET-only filter just like at T0.

import { Scenario } from './scenario.mjs'

const OVERRIDE_HEADERS = ['x-http-method-override', 'x-http-method', 'x-method-override']

function readOverride(req) {
  for (const h of OVERRIDE_HEADERS) {
    const v = req.headers[h]
    if (typeof v === 'string' && v.trim()) return v.trim().toUpperCase()
  }
  return null
}

export const classDef = {
  wstgId: 'WSTG-CONF-06',
  class: 'HTTP Methods / Verb Tampering',
  defenceTiers: [0, 1],
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
    const tier = manifest.defenceTier || 0
    const lineMethod = req.method
    const override = readOverride(req)

    // T1: only GET is accepted in the request line. Every other verb is
    // rejected outright at the edge (the typical middleware "lock down
    // dangerous methods" stance). The override header is the dispatch
    // shortcut the middleware bypass abuses.
    if (tier >= 1 && lineMethod !== 'GET') {
      return { status: 405, body: renderPage('<section style="max-width:520px;margin:64px auto;text-align:center"><h1>Method not allowed</h1><p>This endpoint accepts GET only.</p></section>') }
    }

    // Effective method: at T1 the override header (when present on the
    // permitted line method) wins over the request-line method. At T0 the
    // header is ignored — the T0 bypass is "use any non-GET verb in the
    // request line", no override needed.
    const effective = (tier >= 1 && override) ? override : lineMethod

    // Verb-specific flaw: the access check is enforced only when the
    // effective method is GET. Any other effective method bypasses it.
    if (effective === 'GET') {
      return { status: 403, body: renderPage('<section style="max-width:520px;margin:64px auto;text-align:center"><h1>Access denied</h1><p>You are not authorized to view this resource.</p></section>') }
    }
    return { status: 200, body: renderPage(scenario.protectedBody.replace('{CANARY}', manifest.perDeployCanary)) }
  },

  async fireExploit({ baseUrl, scenario, payload }) {
    // payload is { method, overrideHeader?, overrideValue? }. Backwards-
    // compatible with the old string-method shape produced by older defence
    // packs (a few callers may still pass 'GET'/'POST' directly).
    const desc = typeof payload === 'string' ? { method: payload } : payload
    const headers = {}
    if (desc.overrideHeader && desc.overrideValue) headers[desc.overrideHeader] = desc.overrideValue
    const resp = await fetch(`${baseUrl}${scenario.endpoint.path}`, { method: desc.method, headers })
    return { status: resp.status, body: await resp.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}
