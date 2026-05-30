// WSTG-INPV-18 (4.7.18) — Server-Side Template Injection behaviour.
// The vulnerable render runs in a real Jinja2 backend (localhost), spawned via
// backend.spec; the Node front serves the editor + proxies the render request.
// The canary is a field on the render context object (set into the backend env),
// recovered by injecting template syntax that dumps the context — never in the
// scenario JSON.

import { pathMatchesTemplate } from '../_shared/scenario-common.mjs'
import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-INPV-18',
  class: 'Server-Side Template Injection',
  defenceTiers: [0, 1],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',          // the editor shows {{site.name}} — the engine is observable
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path),

  backend: {
    spec({ scenario, manifest }) {
      const port = 9001
      return {
        cmd: 'python3',
        args: ['classes/wstg-ssti-4.7.18/backends/app.py'],
        port,
        env: {
          PR_BACKEND_PORT: String(port),
          PR_PARAM: scenario.slots.user_input.name,
          PR_PREFIX: scenario.greetingPrefix,
          PR_SITE_NAME: scenario.siteName,
          PR_SITE_TAGLINE: scenario.siteTagline,
          PR_CANARY: manifest.perDeployCanary,
        },
      }
    },
  },

  matchesRequest({ reqUrl, req, scenario }) {
    if (!pathMatchesTemplate(scenario.endpoint.path, reqUrl.pathname)) return false
    return req.method === scenario.endpoint.method || req.method === 'GET'
  },

  async handleRequest({ req, reqUrl, scenario, helpers, renderPage }) {
    if (req.method === 'GET') return { status: 200, body: renderPage(scenario.formBody) }
    const r = await helpers.proxyToBackend(req, reqUrl)   // real Jinja2 render
    return { status: 200, body: renderPage(scenario.resultBody.replace('{OUTPUT}', escapeHtml(r.body))) }
  },

  async fireExploit({ scenario, payload, sessionCookie, helpers }) {
    return helpers.fireScenarioRequest({ scenario, payload, sessionCookie })
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
