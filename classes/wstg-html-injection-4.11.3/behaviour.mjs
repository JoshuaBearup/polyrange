// WSTG-CLNT-03 (4.11.3) — HTML Injection behaviour.
// User input is concatenated unescaped into the page body. The browser
// oracle confirms an injected element with `data-pr-canary` and matching
// text content appears in the rendered DOM — proves HTML rendering, not
// just substring reflection. The canary is attacker-supplied
// (`canaryInjected: true`), so the validator's payload carries the canary
// as the marker text inside the injected element.

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-CLNT-03',
  class: 'HTML Injection',
  defenceTiers: [0, 1],
  Scenario,
  needsSignup: false,
  canaryInjected: true,
  clientSideExecution: true,

  matchesRequest({ reqUrl, req, scenario }) {
    if (req.method !== (scenario.endpoint.method || 'GET')) return false
    return reqUrl.pathname === scenario.endpoint.path
  },

  async handleRequest({ req, reqUrl, scenario, helpers, renderPage }) {
    const userInput = await helpers.extractInput(req, reqUrl, scenario.slots.user_input)
    return {
      status: 200,
      body: renderPage(scenario.body.replaceAll('{INPUT}', userInput)),
    }
  },

  // Fire payload through the class's input slot.
  async fireExploit({ scenario, payload, sessionCookie, helpers }) {
    return helpers.fireScenarioRequest({ scenario, payload, sessionCookie })
  },

  // Browser loads the GET URL with the payload — for HTML injection that's
  // a query/path slot. The browser oracle then walks the DOM for the
  // injected element.
  exploitObservationUrl({ baseUrl, scenario, payload }) {
    const slot = scenario.slots.user_input
    if (slot.location === 'query') {
      const u = new URL(`${baseUrl}${scenario.endpoint.path}`)
      u.searchParams.set(slot.name, payload)
      return u.toString()
    }
    if (slot.location === 'path-segment') {
      return `${baseUrl}${scenario.endpoint.path.replace(new RegExp(`[:{]${slot.name}\\}?`), encodeURIComponent(payload))}`
    }
    return null
  },

  // Fallback (non-browser callers). The browser oracle's [data-pr-canary]
  // element-text check is the real success signal.
  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}
