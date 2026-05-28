// WSTG-CLNT-06 (4.11.6) — Client-side Resource Manipulation behaviour.
// User-controlled URL lands in a resource-loading sink (img/iframe/script
// src). Browser fetches the attacker-supplied URL; off-origin signal fires.

import { Scenario } from './scenario.mjs'

function escAttr(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

export const classDef = {
  wstgId: 'WSTG-CLNT-06',
  class: 'Client-side Resource Manipulation',
  defenceTiers: [0, 1],
  Scenario,
  needsSignup: false,
  canaryInjected: true,
  clientSideExecution: true,

  matchesRequest({ reqUrl, req, scenario }) {
    return req.method === 'GET' && reqUrl.pathname === scenario.endpoint.path
  },

  async handleRequest({ req, reqUrl, scenario, helpers, renderPage }) {
    const userInput = await helpers.extractInput(req, reqUrl, scenario.slots.user_input)
    // Quote the attribute value but DO NOT validate the URL — that's the bug.
    const tag = scenario.sinkTag
    const sinkHtml = tag === 'iframe'
      ? `<iframe src="${escAttr(userInput)}" style="width:100%;height:240px;border:1px solid #ddd"></iframe>`
      : tag === 'script'
        ? `<script src="${escAttr(userInput)}"></script>`
        : `<img src="${escAttr(userInput)}" alt="" style="max-width:100%">`
    return {
      status: 200,
      body: renderPage(scenario.body.replaceAll('{SINK}', sinkHtml)),
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
