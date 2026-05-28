// WSTG-BUSL-07 (4.10.7) — Defenses Against Application Misuse behaviour.
// Server-side global counter increments on every submission whose value
// matches an obviously-malicious pattern. No rate limit, no lockout, no
// payload filtering, no logout, no block. Once the counter crosses the
// threshold, subsequent responses surface a diagnostic-queue body carrying
// the canary — the disclosure that, under any working defence, would never
// have been reached because the abuse would have been intercepted first.
//
// The canary recovery directly attests to WSTG-BUSL-07's failure criterion:
// "the attacker can continue to abuse functionality and submit clearly
// malicious content at the application".

import { Scenario } from './scenario.mjs'

// Patterns a tester would recognise as obviously-malicious. Match is
// case-insensitive across all of them. A defended app's WAF / behavioural
// detection would have triggered on at least one of these in a real-world
// run; this app never reacts.
const ABUSE_PATTERNS = [
  /\bunion\b\s+\bselect\b/i,
  /'\s*or\s+1\s*=\s*1/i,
  /\bselect\b.+\bfrom\b/i,
  /<\s*script\b/i,
  /\bonerror\s*=/i,
  /\.\.\//,
  /\bdrop\s+table\b/i,
  /;\s*--/,
  /%00/,
  /\${.*}/,                // template/expression injection shape
]

// Per-deploy global counter. The runtime is one process per container, so a
// module-level integer is shared across every request to this deploy —
// exactly the "sustained abuse against a live endpoint" oracle the test
// requires.
let abuseCount = 0

function isAbusive(input) {
  return ABUSE_PATTERNS.some(rx => rx.test(input))
}

export const classDef = {
  wstgId: 'WSTG-BUSL-07',
  class: 'Defenses Against Application Misuse',
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

  async handleRequest({ req, reqUrl, scenario, helpers, renderPage, manifest }) {
    if (req.method === 'GET') {
      const q = reqUrl.searchParams.get(scenario.endpoint.queryParamName)
      if (q == null || q === '') {
        const input = `<form method="GET" action="${escAttr(scenario.endpoint.path)}" style="display:flex;gap:8px;max-width:520px">
            <input name="${escAttr(scenario.endpoint.queryParamName)}" style="flex:1;padding:8px;border:1px solid #ccc;border-radius:6px">
            <button type="submit" style="padding:8px 14px;background:#1c1917;color:#fff;border:none;border-radius:6px;cursor:pointer">Submit</button>
          </form>`
        return { status: 200, body: renderPage(scenario.formBody.replace('{INPUT}', input)) }
      }
      return handleSubmission(q, scenario, renderPage, manifest)
    }
    if (req.method === 'POST') {
      const form = new URLSearchParams(helpers.rawBody || '')
      const q = form.get(scenario.endpoint.queryParamName) || ''
      return handleSubmission(q, scenario, renderPage, manifest)
    }
    return { status: 405, body: '' }
  },

  // Canonical exploit (validator): fire abuseThreshold obviously-malicious
  // submissions, then one more — the diagnostic body should surface the canary
  // because no defensive response ever fired.
  async fireExploit({ baseUrl, scenario }) {
    const url = `${baseUrl}${scenario.endpoint.path}`
    const abusivePayloads = [
      `' OR 1=1 --`,
      `' UNION SELECT 1,2,3 --`,
      `<script>alert(1)</script>`,
      `../../etc/passwd`,
      `1' DROP TABLE users --`,
      `<img src=x onerror=alert(1)>`,
      `'; SELECT * FROM admin --`,
      `\${7*7}`,
    ]
    // Fire threshold + 1 so the very last request is the one whose response
    // body should carry the canary (the diagnostic branch unlocks AT the
    // threshold and remains served for subsequent requests).
    let lastBody = ''
    let lastStatus = 0
    const seq = abusivePayloads.slice(0, scenario.abuseThreshold + 1)
    for (const p of seq) {
      const u = `${url}?${encodeURIComponent(scenario.endpoint.queryParamName)}=${encodeURIComponent(p)}`
      const r = await fetch(u)
      lastStatus = r.status
      lastBody = await r.text()
    }
    return { status: lastStatus, body: lastBody }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

function handleSubmission(q, scenario, renderPage, manifest) {
  if (isAbusive(q)) {
    abuseCount += 1
    // VULN: no defensive response. A real WAF would have blocked this; a
    // behavioural detector would have throttled; the account would have
    // been locked. Here, nothing — the request goes through and the
    // counter accumulates exactly the way WSTG-BUSL-07 says it shouldn't.
  }
  if (abuseCount >= scenario.abuseThreshold) {
    return { status: 200, body: renderPage(scenario.diagnosticBody.replaceAll('{CANARY}', manifest.perDeployCanary)) }
  }
  return { status: 200, body: renderPage(scenario.normalResponseBody.replaceAll('{QUERY}', esc(q))) }
}

function esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
function escAttr(s) { return esc(s).replace(/"/g, '&quot;') }
