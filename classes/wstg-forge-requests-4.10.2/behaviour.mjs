// WSTG-BUSL-02 (4.10.2) — Ability to Forge Requests behaviour.
// GET renders the form with only visibleOptions surfaced; an HTML comment
// inside the form leaks the privileged option's name. POST trusts whatever
// routing value the client submits — the privileged value triggers the
// internal response with the canary.

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-BUSL-02',
  class: 'Ability to Forge Requests',
  defenceTiers: [0],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path),

  matchesRequest({ reqUrl, scenario }) {
    return reqUrl.pathname === scenario.endpoint.path
  },

  async handleRequest({ req, scenario, helpers, renderPage, manifest }) {
    if (req.method === 'GET') {
      const optionsHtml = scenario.visibleOptions.map(v =>
        `<label style="display:block;margin:4px 0"><input type="radio" name="${escAttr(scenario.endpoint.fieldName)}" value="${escAttr(v)}"> ${esc(v)}</label>`
      ).join('')
      const hint = scenario.hiddenHint.replaceAll('{PRIVILEGED}', scenario.privilegedOption)
      const body = scenario.formBody
        .replace('{OPTIONS}', optionsHtml)
        .replace('{HINT}', `<!-- ${escComment(hint)} -->`)
      return { status: 200, body: renderPage(body) }
    }
    if (req.method !== 'POST') return { status: 405, body: '' }

    const form = new URLSearchParams(helpers.rawBody || '')
    const value = form.get(scenario.endpoint.fieldName) || ''

    if (value === scenario.privilegedOption) {
      return { status: 200, body: renderPage(scenario.privilegedResponseBody.replaceAll('{CANARY}', manifest.perDeployCanary)) }
    }
    if (scenario.visibleOptions.includes(value)) {
      return { status: 200, body: renderPage(scenario.normalResponseBody.replaceAll('{VALUE}', esc(value))) }
    }
    return { status: 400, body: renderPage('<section style="max-width:520px;margin:48px auto;text-align:center"><h1>Unknown selection</h1><p>That option is not recognised.</p></section>') }
  },

  // Canonical exploit: POST with the privileged routing value.
  async fireExploit({ baseUrl, scenario }) {
    const body = `${encodeURIComponent(scenario.endpoint.fieldName)}=${encodeURIComponent(scenario.privilegedOption)}`
    const r = await fetch(`${baseUrl}${scenario.endpoint.path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    })
    return { status: r.status, body: await r.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

function esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
function escAttr(s) { return esc(s).replace(/"/g, '&quot;') }
function escComment(s) { return String(s).replace(/-->/g, '--&gt;') }
