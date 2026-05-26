// WSTG-INPV-02 (4.7.2) — Stored XSS behaviour.
// Stateless Node + an in-memory store (single machine, --ha=false). Submitted
// values are stored raw and rendered UNESCAPED on the view page. Two-step
// exploit: POST a payload, then GET the view where it reflects unescaped.

import { Scenario } from './scenario.mjs'

// Per-process store. Single machine per deploy, so this persists across the
// submit→view round-trip for the life of the container.
const STORE = []

export const classDef = {
  wstgId: 'WSTG-INPV-02',
  class: 'Stored XSS',
  defenceTiers: [0, 1, 2, 3, 4],
  Scenario,
  needsSignup: false,
  canaryInjected: true,       // canary is the attacker's stored marker, not pre-placed
  clientSideExecution: true,  // validated by a real headless browser, not substring reflection

  matchesRequest({ reqUrl, req, scenario }) {
    if (req.method === scenario.submitEndpoint.method && reqUrl.pathname === scenario.submitEndpoint.path) return true
    if (req.method === 'GET' && reqUrl.pathname === scenario.viewPath) return true
    // GET of the submit path renders the form host page
    if (req.method === 'GET' && reqUrl.pathname === scenario.submitEndpoint.path) return true
    return false
  },

  async handleRequest({ req, reqUrl, scenario, helpers, renderPage }) {
    const submit = scenario.submitEndpoint

    // Submit: store the raw value (the stored-XSS sink stores unescaped)
    if (req.method === submit.method && reqUrl.pathname === submit.path) {
      const value = await helpers.extractInput(req, reqUrl, scenario.slots.user_input)
      if (value && value.trim()) STORE.push(String(value))
      // Redirect to the view page after submission (PRG pattern)
      return { status: 302, body: '', headers: { Location: scenario.viewPath } }
    }

    // View: render all stored submissions UNESCAPED (the vulnerability)
    if (req.method === 'GET' && reqUrl.pathname === scenario.viewPath) {
      const items = STORE.map(v => scenario.itemTemplate.replace('{VALUE}', v)).join('\n')
      return { status: 200, body: renderPage(scenario.viewBody.replace('{ITEMS}', items)) }
    }

    // GET submit path: show the form host page
    return { status: 200, body: renderPage(scenario.submitFormBody) }
  },

  // Two-step: POST the payload to the submit endpoint, then GET the view page
  // where it reflects. Returns the view response (where the canary appears).
  async fireExploit({ baseUrl, scenario, payload, helpers }) {
    const submit = scenario.submitEndpoint
    const loc = scenario.slots.user_input.location
    const headers = {}
    let body
    if (loc === 'body-json') {
      headers['Content-Type'] = 'application/json'
      body = JSON.stringify({ [scenario.slots.user_input.name]: payload })
    } else {
      headers['Content-Type'] = 'application/x-www-form-urlencoded'
      body = `${encodeURIComponent(scenario.slots.user_input.name)}=${encodeURIComponent(payload)}`
    }
    await fetch(`${baseUrl}${submit.path}`, { method: submit.method, headers, body, redirect: 'manual' })
    // Now view
    return helpers.fetchWithCookie(`${baseUrl}${scenario.viewPath}`, null)
  },

  // The payload is already stored by fireExploit; execution happens when a
  // browser loads the view page and the stored value renders unescaped.
  exploitObservationUrl({ baseUrl, scenario }) {
    return `${baseUrl}${scenario.viewPath}`
  },

  // Kept for non-browser callers; the browser oracle is the real success check.
  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}
