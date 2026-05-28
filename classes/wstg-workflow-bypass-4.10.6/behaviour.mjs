// WSTG-BUSL-06 (4.10.6) — Circumvention of Work Flows behaviour.
// A single checkout page driven by the client-controlled checkout_stage cookie
// (cart -> payment -> complete). The fulfilment branch (stage=complete) delivers
// the product with NO server-side check that payment happened — so forging the
// cookie to "complete" reaches fulfilment (the canary) without paying.

import { Scenario } from './scenario.mjs'

function getCookie(req, name) {
  const c = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='))
  return c ? c.slice(name.length + 1) : null
}

export const classDef = {
  wstgId: 'WSTG-BUSL-06',
  class: 'Circumvention of Work Flows',
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
    const base = scenario.endpoint.path
    const stage = getCookie(req, 'checkout_stage') || 'cart'

    if (req.method === 'POST') {
      // Legitimate forward transitions in the intended order.
      const action = new URLSearchParams(helpers.rawBody || '').get('action')
      const next = action === 'pay' ? 'complete' : action === 'to-payment' ? 'payment' : stage
      return { status: 302, headers: { Location: base, 'Set-Cookie': `checkout_stage=${next}; Path=/` }, body: '' }
    }

    // VULNERABLE: the fulfilment branch trusts the client-controlled stage cookie
    // with no check that payment was actually completed.
    if (stage === 'complete') {
      return { status: 200, body: renderPage(scenario.fulfillmentBody.replace('{CANARY}', manifest.perDeployCanary)) }
    }
    if (stage === 'payment') {
      return { status: 200, body: renderPage(paymentPage(scenario)) }
    }
    // default: cart (review) step
    return {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'Set-Cookie': 'checkout_stage=cart; Path=/' },
      body: renderPage(cartPage(scenario)),
    }
  },

  // Reference exploit: forge checkout_stage=complete to reach fulfilment without payment.
  async fireExploit({ baseUrl, scenario, helpers }) {
    return helpers.fetchWithCookie(`${baseUrl}${scenario.endpoint.path}`, 'checkout_stage=complete')
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

function cartPage(scenario) {
  return `<section style="max-width:520px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 4px">Checkout — review</h2>
  <p style="color:#666;margin:0 0 12px">${escapeHtml(scenario.cartIntro)}</p>
  <article style="border:1px solid #e5e5e5;border-radius:8px;padding:14px;margin:8px 0;background:#fafafa">
    <div style="font-weight:600">${escapeHtml(scenario.productLabel)}</div>
    <div style="font-size:13px;color:#666">In your cart · step 1 of 3</div>
  </article>
  <form method="POST" action="${scenario.endpoint.path}"><input type="hidden" name="action" value="to-payment">
    <button type="submit" style="padding:9px 14px">Proceed to payment</button></form>
</section>`
}
function paymentPage(scenario) {
  return `<section style="max-width:520px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 8px">Payment — step 2 of 3</h2>
  <p style="color:#666;margin:0 0 12px">Enter payment to complete your order for ${escapeHtml(scenario.productLabel)}. Your ${escapeHtml(scenario.productLabel)} is delivered once the order is complete.</p>
  <form method="POST" action="${scenario.endpoint.path}" style="display:flex;flex-direction:column;gap:10px">
    <input type="hidden" name="action" value="pay">
    <label>Card number<input name="card" placeholder="4111 1111 1111 1111" style="display:block;width:100%;padding:8px"></label>
    <button type="submit" style="padding:9px 14px">Pay &amp; complete order</button>
  </form>
</section>`
}
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
