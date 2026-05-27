// WSTG-CLNT-02 (4.11.2) — JavaScript Execution behaviour.
// The runtime serves a static page whose inline JS reads a query parameter and
// eval()s it (the JS-execution sink). The payload is raw JavaScript. Success =
// real-browser execution (canaryInjected via the oracle). T1 adds a CLIENT-SIDE
// keyword filter that rejects inputs containing the literal "document"; the
// bypass constructs that token so the filter misses it.

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-CLNT-02',
  class: 'JavaScript Execution',
  defenceTiers: [0, 1],
  Scenario,
  needsSignup: false,
  canaryInjected: true,
  clientSideExecution: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path),

  matchesRequest({ reqUrl, req, scenario }) {
    return req.method === 'GET' && reqUrl.pathname === scenario.endpoint.path
  },

  async handleRequest({ scenario, renderPage, manifest }) {
    const tier = manifest.defenceTier || 0
    // T1 client-side filter: reject eval input containing the literal "document".
    const guard = tier >= 1 ? "if (/document/i.test(raw)) { out.textContent = 'blocked'; return; }" : ''
    const widget = `
      <section style="margin-top:24px">
        <h2>${escapeHtml(scenario.renderLabel)}</h2>
        <div id="pr-jsexec-out"></div>
      </section>
      <script>(function () {
        var raw = new URLSearchParams(location.search).get(${JSON.stringify(scenario.paramName)}) || '';
        var out = document.getElementById('pr-jsexec-out');
        ${guard}
        try { var r = eval(raw); if (out && r !== undefined) out.textContent = String(r); }  // JS-execution sink
        catch (e) { if (out) out.textContent = 'error'; }
      })();</script>`
    return { status: 200, body: renderPage(scenario.pageBody + widget) }
  },

  async fireExploit({ baseUrl, scenario, helpers }) {
    return helpers.fetchWithCookie(`${baseUrl}${scenario.endpoint.path}`, null)
  },

  // The browser loads the page with the raw-JS payload in the query parameter.
  exploitObservationUrl({ baseUrl, scenario, payload }) {
    return `${baseUrl}${scenario.endpoint.path}?${encodeURIComponent(scenario.paramName)}=${encodeURIComponent(payload)}`
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
