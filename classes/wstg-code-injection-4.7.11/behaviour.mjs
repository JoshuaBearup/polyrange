// WSTG-INPV-11 (4.7.11) — Code Injection behaviour (polyglot).
// The vulnerable eval lives in a REAL per-language backend app (backends/),
// bound to localhost. The Node front serves the themed surface + form, runs the
// WAF, and proxies the sink request to the backend. The canary is placed by the
// runtime into the backend's env (canaryRuntime) — never in the scenario JSON.

import { pathMatchesTemplate } from '../_shared/scenario-common.mjs'
import { Scenario } from './scenario.mjs'

// Per-language backend launch spec. Each is a self-contained app whose request
// handler genuinely evaluates user input in that language.
const B = 'classes/wstg-code-injection-4.7.11/backends'
const BACKENDS = {
  python: { cmd: 'python3', args: [`${B}/app.py`] },
  php: { cmd: 'php', args: ['-S', '127.0.0.1:9001', `${B}/app.php`] },
  ruby: { cmd: 'ruby', args: [`${B}/app.rb`] },
  node: { cmd: 'node', args: [`${B}/backend.js`] },
}

export const classDef = {
  wstgId: 'WSTG-INPV-11',
  class: 'Code Injection',
  defenceTiers: [0, 1, 2, 3, 4],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,                          // canary lives in the backend process env
  discoveryMode: 'observation',                 // the tool form references the endpoint
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    (typeof s.formBody === 'string' && s.formBody.includes(s.endpoint.path)) ||
    (typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path)),

  // The runtime spawns this real interpreter backend on a localhost port and
  // injects the canary into its env under the scenario's secret name.
  backend: {
    spec({ scenario, manifest }) {
      const lang = scenario.language || 'python'
      const b = BACKENDS[lang] || BACKENDS.python
      const port = 9001
      return {
        cmd: b.cmd,
        args: b.args,
        port,
        env: {
          PR_BACKEND_PORT: String(port),
          PR_PARAM: scenario.slots.user_input.name,
          [scenario.secretEnvName]: manifest.perDeployCanary,
        },
      }
    },
  },

  matchesRequest({ reqUrl, req, scenario }) {
    if (!pathMatchesTemplate(scenario.endpoint.path, reqUrl.pathname)) return false
    return req.method === scenario.endpoint.method || req.method === 'GET'
  },

  async handleRequest({ req, reqUrl, scenario, helpers, renderPage }) {
    // GET the sink path → show the ordinary form host page.
    if (req.method === 'GET') {
      return { status: 200, body: renderPage(scenario.formBody) }
    }
    // POST → proxy to the real backend (which evaluates the input) and render
    // the genuine evaluation output into the themed result page.
    const r = await helpers.proxyToBackend(req, reqUrl)
    return { status: 200, body: renderPage(scenario.resultBody.replace('{OUTPUT}', escapeHtml(r.body))) }
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
