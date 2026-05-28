// WSTG-CLNT-04 (4.11.4) — Client-side URL Redirect (open redirect).
// The runtime serves a static page whose inline JS reads the redirect-target
// query parameter and assigns it to location.href with NO validation. The
// real-browser oracle confirms the browser navigates off-origin to the
// attacker-supplied URL (carrying the canary marker).

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-CLNT-04',
  class: 'Client-side URL Redirect (open redirect)',
  defenceTiers: [0],
  Scenario,
  needsSignup: false,
  canaryInjected: true,          // attacker supplies the canary in the redirect target
  clientSideExecution: true,     // validated by the real-browser oracle (off-origin nav)
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path),

  matchesRequest({ reqUrl, req, scenario }) {
    return req.method === 'GET' && reqUrl.pathname === scenario.endpoint.path
  },

  async handleRequest({ scenario, renderPage }) {
    const param = JSON.stringify(scenario.redirectParam)
    const widget = `
      <section style="max-width:520px;margin:0 auto;text-align:center;padding:24px">
        ${scenario.pageBody}
        <p id="pr-redir-status" style="color:#666;margin-top:16px">Preparing your destination…</p>
      </section>
      <script>(function () {
        var dest = new URLSearchParams(location.search).get(${param});
        if (dest) { window.location.href = dest; }   // VULNERABLE: no validation of the redirect target
      })();</script>`
    return { status: 200, body: renderPage(widget) }
  },

  // HTTP fetch only confirms the page is served; the real check is the browser
  // oracle observing the off-origin navigation.
  async fireExploit({ baseUrl, scenario, helpers }) {
    return helpers.fetchWithCookie(`${baseUrl}${scenario.endpoint.path}`, null)
  },

  // The browser loads the page with the attacker URL in the redirect parameter.
  exploitObservationUrl({ baseUrl, scenario, payload }) {
    return `${baseUrl}${scenario.endpoint.path}?${encodeURIComponent(scenario.redirectParam)}=${encodeURIComponent(payload)}`
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}
