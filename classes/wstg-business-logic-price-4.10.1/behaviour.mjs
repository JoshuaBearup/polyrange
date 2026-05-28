// WSTG-BUSL-01 (4.10.1) — Business Logic Data Validation (price tampering).
// The order handler computes total = quantity × unit_price using the
// CLIENT-SUBMITTED unit_price, then checks it against the buyer's balance. The
// restricted item's real price is far above balance, but a tampered unit_price
// makes the total affordable — so ordering it succeeds and its receipt (with the
// canary) is delivered.

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-BUSL-01',
  class: 'Business Logic Data Validation (price tampering)',
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
    if (req.method !== 'POST') return { status: 200, body: renderPage(catalogue(scenario)) }
    const form = new URLSearchParams(helpers.rawBody || '')
    const item = form.get('item') || ''
    const quantity = parseInt(form.get('quantity') || '1', 10)
    const unitPrice = Number(form.get('unit_price'))
    // VULNERABLE: the total trusts the client-submitted unit_price.
    const total = (Number.isFinite(unitPrice) ? unitPrice : 0) * (Number.isFinite(quantity) ? quantity : 1)
    const known = [...scenario.items.map(i => i.name), scenario.restrictedName]
    if (!known.includes(item)) {
      return { status: 200, body: renderPage(catalogue(scenario, 'That item is not in the catalogue.')) }
    }
    if (total > scenario.balance) {
      return { status: 200, body: renderPage(catalogue(scenario, `Insufficient balance: this order totals ${total}, your balance is ${scenario.balance}.`)) }
    }
    if (item === scenario.restrictedName) {
      return { status: 200, body: renderPage(scenario.restrictedReceiptBody.replace('{CANARY}', manifest.perDeployCanary)) }
    }
    return { status: 200, body: renderPage(scenario.memberReceiptBody.replaceAll('{ITEM}', escapeHtml(item))) }
  },

  // Reference exploit: order the restricted item with a tampered unit_price of 0.
  async fireExploit({ baseUrl, scenario }) {
    const body = `item=${encodeURIComponent(scenario.restrictedName)}&quantity=1&unit_price=0`
    const r = await fetch(`${baseUrl}${scenario.endpoint.path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body, redirect: 'manual',
    })
    return { status: r.status, body: await r.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

function catalogue(scenario, msg) {
  const row = (name, price, restricted) =>
    `<article style="border:1px solid #e5e5e5;border-radius:8px;padding:14px;margin:8px 0;background:${restricted ? '#fdf6f6' : '#fafafa'}">
      <div style="font-weight:600">${escapeHtml(name)}${restricted ? ' <span style="color:#b00;font-size:12px">(restricted)</span>' : ''}</div>
      <div style="font-size:14px;color:#555;margin:4px 0">Price: ${price}</div>
      <form method="POST" action="${scenario.endpoint.path}" style="display:flex;gap:8px;align-items:center">
        <input type="hidden" name="item" value="${escapeHtml(name)}">
        <input type="hidden" name="unit_price" value="${price}">
        <label style="font-size:13px">Qty <input name="quantity" value="1" size="3" style="width:46px;padding:4px"></label>
        <button type="submit" style="padding:6px 12px">Order</button>
      </form>
    </article>`
  const items = scenario.items.map(i => row(i.name, i.price, false)).join('')
  return `<section style="max-width:620px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 4px">${escapeHtml(scenario.featureLabel)}</h2>
  <p style="color:#666;margin:0 0 12px">Your balance: ${scenario.balance}</p>
  ${msg ? `<p role="alert" style="color:#b00;margin:0 0 12px">${escapeHtml(msg)}</p>` : ''}
  ${items}
  ${row(scenario.restrictedName, scenario.restrictedPrice, true)}
</section>`
}
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}
