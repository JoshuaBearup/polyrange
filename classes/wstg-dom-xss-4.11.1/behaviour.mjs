// WSTG-CLNT-01 (4.11.1) — DOM-Based XSS behaviour.
// The runtime serves a STATIC page; its inline JS reads location.hash (source)
// into #pr-domxss-out's innerHTML (sink). The server never sees the payload
// (it's in the fragment). Success = real-browser execution (canaryInjected via
// the oracle). T1 adds a CLIENT-SIDE sanitizer (strips onerror); the bypass
// uses a different handler (svg onload).

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-CLNT-01',
  class: 'DOM-Based XSS',
  defenceTiers: [0, 1],
  Scenario,
  needsSignup: false,
  canaryInjected: true,                // attacker supplies the canary marker in the payload
  clientSideExecution: true,           // validated by the real-browser oracle, not reflection
  discoveryMode: 'observation',        // the feature + its hash-reading JS are observable
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path),

  matchesRequest({ reqUrl, req, scenario }) {
    return req.method === 'GET' && reqUrl.pathname === scenario.endpoint.path
  },

  async handleRequest({ scenario, renderPage, manifest }) {
    const tier = manifest.defenceTier || 0
    // T1 client-side sanitizer strips the onerror handler; T0 passes raw.
    const expr = tier >= 1 ? "raw.replace(/onerror/gi, '')" : "raw"
    const widget = `
      <section style="margin-top:24px">
        <h2>${escapeHtml(scenario.renderLabel)}</h2>
        <div id="pr-domxss-out"></div>
      </section>
      <script>(function () {
        var raw = decodeURIComponent((location.hash || '').slice(1));
        var el = document.getElementById('pr-domxss-out');
        if (el) { el.innerHTML = ${expr}; }   // DOM source -> sink, no server involvement
      })();</script>`
    return { status: 200, body: renderPage(scenario.pageBody + widget) }
  },

  // HTTP fetch only confirms the page is served; the real check is the browser
  // oracle navigating to the fragment URL below.
  async fireExploit({ baseUrl, scenario, helpers }) {
    return helpers.fetchWithCookie(`${baseUrl}${scenario.endpoint.path}`, null)
  },

  // The browser loads the page with the payload in the URL FRAGMENT (the source).
  exploitObservationUrl({ baseUrl, scenario, payload }) {
    return `${baseUrl}${scenario.endpoint.path}#${encodeURIComponent(payload)}`
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
