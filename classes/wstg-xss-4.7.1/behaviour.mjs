// WSTG-INPV-01 — Reflected XSS behaviour.
// Imports the Scenario schema; field names not re-declared anywhere.

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-INPV-01',
  class: 'Reflected XSS',
  defenceTiers: [0, 1, 2, 3, 4],
  Scenario,
  needsSignup: false,
  canaryInjected: true,       // canary is the attacker's injected marker, not pre-placed
  clientSideExecution: true,  // validated by a real headless browser, not substring reflection

  // ============================================================
  // Runtime: request matching + handling
  // ============================================================
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

  // ============================================================
  // Deploy validator: fire a payload through the class's endpoint
  // ============================================================
  async fireExploit({ scenario, payload, sessionCookie, helpers }) {
    // Honours scenario.endpoint.method + scenario.slots.user_input.location
    return helpers.fireScenarioRequest({ scenario, payload, sessionCookie })
  },

  // URL a real browser loads to OBSERVE execution. Reflected XSS executes when
  // the victim loads the URL carrying the payload, so for a query/path slot we
  // hand back the GET URL with the payload in place. (Body/header-reflected XSS
  // isn't browser-navigable this way; returns null → reported unsolvable.)
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

  // Kept for non-browser callers; the browser oracle is the real success check.
  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) => {
    return responseBody.includes(perDeployCanary)
  },
}
