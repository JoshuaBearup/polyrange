// WSTG-CLNT-05 (4.11.5) — CSS Injection behaviour.
// User input is interpolated unsafely into a CSS context. The browser's
// off-origin-request check catches the injected `url(...)` exfil.

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-CLNT-05',
  class: 'CSS Injection',
  defenceTiers: [0],
  Scenario,
  needsSignup: false,
  canaryInjected: true,
  clientSideExecution: true,

  matchesRequest({ reqUrl, req, scenario }) {
    return req.method === 'GET' && reqUrl.pathname === scenario.endpoint.path
  },

  async handleRequest({ req, reqUrl, scenario, helpers, renderPage }) {
    const userInput = await helpers.extractInput(req, reqUrl, scenario.slots.user_input)
    return {
      status: 200,
      body: renderPage(scenario.body.replaceAll('{INPUT}', userInput)),
    }
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
