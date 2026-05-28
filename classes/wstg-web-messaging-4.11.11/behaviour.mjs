// WSTG-CLNT-11 (4.11.11) — Web Messaging behaviour.
// Page exposes a postMessage handler with NO origin check; whatever data
// arrives is written to a window global. To make the bug observable in a
// single page-load (no separate attacker frame), the page also self-posts
// the URL-supplied value at load — demonstrating the exact handler path
// that an attacker frame would exercise. Browser oracle then finds the
// canary in window.__pr_marker.

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-CLNT-11',
  class: 'Web Messaging',
  defenceTiers: [0],
  Scenario,
  needsSignup: false,
  canaryInjected: true,
  clientSideExecution: true,

  matchesRequest({ reqUrl, req, scenario }) {
    return req.method === 'GET' && reqUrl.pathname === scenario.endpoint.path
  },

  async handleRequest({ reqUrl, scenario, renderPage }) {
    const paramName = scenario.slots.user_input.name
    const body = `${scenario.body}
<script>
(function () {
  // VULN: postMessage handler with no origin check. Any frame, any host
  // can deliver data, and it gets written to a window global that the
  // SDK code reads downstream.
  window.addEventListener('message', function (e) {
    try { window.__pr_marker = e.data; } catch (err) {}
  });
  // Self-trigger from URL so a single page-load exercises the bug — this
  // is what an attacker frame would do.
  try {
    var v = new URLSearchParams(location.search).get(${JSON.stringify(paramName)});
    if (v) window.postMessage(v, '*');
  } catch (e) {}
})();
</script>`
    return { status: 200, body: renderPage(body) }
  },

  async fireExploit({ scenario, payload, sessionCookie, helpers }) {
    return helpers.fireScenarioRequest({ scenario, payload, sessionCookie })
  },

  exploitObservationUrl({ baseUrl, scenario, payload }) {
    const slot = scenario.slots.user_input
    const u = new URL(`${baseUrl}${scenario.endpoint.path}`)
    u.searchParams.set(slot.name, payload)
    return u.toString()
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}
