// WSTG-BUSL-05 (4.10.5) — Function Usage Limits behaviour.
// The counter is the value of a client-controlled cookie. Server reads it,
// renders progress, and gates the reward at threshold. No server-side
// verification — setting the cookie to >= threshold unlocks immediately.

import { Scenario } from './scenario.mjs'

function getCookie(req, name) {
  const c = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='))
  return c ? c.slice(name.length + 1) : null
}

export const classDef = {
  wstgId: 'WSTG-BUSL-05',
  class: 'Function Usage Limits',
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

  async handleRequest({ req, scenario, renderPage, manifest }) {
    const raw = getCookie(req, scenario.counterCookieName)
    const count = Math.max(0, parseInt(raw || '0', 10) || 0)

    if (req.method === 'POST') {
      // Intended flow: each POST adds +1 progress. Server respects the cookie
      // value as authoritative — the whole point: the limit is client-trusted.
      const next = count + 1
      return {
        status: 302,
        headers: {
          Location: scenario.endpoint.path,
          'Set-Cookie': `${scenario.counterCookieName}=${next}; Path=/; SameSite=Lax`,
        },
        body: '',
      }
    }

    if (req.method !== 'GET') return { status: 405, body: '' }

    if (count >= scenario.threshold) {
      return { status: 200, body: renderPage(scenario.rewardBody.replaceAll('{CANARY}', manifest.perDeployCanary)) }
    }

    const explanation = scenario.explanationBody.replaceAll('{THRESHOLD}', String(scenario.threshold))
    const main = scenario.normalBody.replaceAll('{COUNT}', String(count))
    return { status: 200, body: renderPage(`${explanation}\n${main}`) }
  },

  // Canonical exploit: set the counter cookie to the threshold directly.
  async fireExploit({ baseUrl, scenario, helpers }) {
    const cookie = `${scenario.counterCookieName}=${scenario.threshold}`
    return helpers.fetchWithCookie(`${baseUrl}${scenario.endpoint.path}`, cookie)
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}
