// WSTG-INPV-19 (4.7.19) — SSRF behaviour.
// The public feature does a REAL server-side fetch of a user-supplied URL. An
// internal service (localhost-bound, spawned via backend.spec) serves the
// canary as an "internal config". The attacker pivots the fetch to the internal
// service. Containment: the fetch is restricted to loopback/private targets, so
// the internal canary is reachable but the box can't proxy the open internet.

import dns from 'node:dns/promises'
import net from 'node:net'
import { pathMatchesTemplate } from '../_shared/scenario-common.mjs'
import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-INPV-19',
  class: 'Server-Side Request Forgery',
  defenceTiers: [0, 1, 2, 3, 4],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,                  // canary lives in the internal service, not the scenario
  discoveryMode: 'lead',                // the surface hint references the internal service
  discoveryTargetPath: (s) => s.internalPath,
  discoveryStaticOk: (s) =>
    typeof s.internalHint === 'string' && s.internalHint.includes(s.internalPath) &&
    /127\.0\.0\.1|localhost/.test(s.internalHint),

  // The internal service (the pivot target) — loopback-bound, serving the canary.
  backend: {
    spec({ scenario, manifest }) {
      return {
        cmd: 'node',
        args: ['classes/wstg-ssrf-4.7.19/backends/internal.mjs'],
        port: scenario.internalPort,
        env: {
          PR_BACKEND_PORT: String(scenario.internalPort),
          PR_CANARY: manifest.perDeployCanary,
          PR_INTERNAL_PATH: scenario.internalPath,
        },
      }
    },
  },

  matchesRequest({ reqUrl, req, scenario }) {
    if (!pathMatchesTemplate(scenario.endpoint.path, reqUrl.pathname)) return false
    return req.method === scenario.endpoint.method || req.method === 'GET'
  },

  async handleRequest({ req, reqUrl, scenario, helpers, renderPage }) {
    // GET → the form + the (rendered) internal hint so the lead is discoverable.
    if (req.method === 'GET') {
      const hint = `<aside class="integration-note"><p>${escapeHtml(scenario.internalHint)}</p></aside>`
      return { status: 200, body: renderPage(scenario.formBody + hint) }
    }
    // POST → real server-side fetch of the user URL (SSRF sink), loopback/private only.
    const target = await helpers.extractInput(req, reqUrl, scenario.slots.user_input)
    const out = await safeFetch(String(target || ''))
    return { status: 200, body: renderPage(scenario.resultBody.replace('{OUTPUT}', escapeHtml(out))) }
  },

  async fireExploit({ baseUrl, scenario, payload, helpers }) {
    const slot = scenario.slots.user_input
    const method = scenario.endpoint.method
    let url = `${baseUrl}${scenario.endpoint.path}`
    if (slot.location === 'query' || method === 'GET') {
      url += `?${encodeURIComponent(slot.name)}=${encodeURIComponent(payload)}`
      return helpers.fetchWithCookie(url, null)
    }
    const headers = {}
    let body
    if (slot.location === 'body-json') {
      headers['Content-Type'] = 'application/json'; body = JSON.stringify({ [slot.name]: payload })
    } else {
      headers['Content-Type'] = 'application/x-www-form-urlencoded'
      body = `${encodeURIComponent(slot.name)}=${encodeURIComponent(payload)}`
    }
    const resp = await fetch(url, { method, headers, body })
    return { status: resp.status, body: await resp.text() }
  },

  proofTarget: (s) => `${s.endpoint.method} ${s.endpoint.path} → SSRF to http://127.0.0.1:${s.internalPort}${s.internalPath}`,

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

// Real server-side fetch, but only to loopback/private targets (containment).
// Returns a string (fetched body, capped, or an error/blocked message).
async function safeFetch(rawUrl) {
  let u
  try { u = new URL(rawUrl) } catch { return 'error: invalid URL' }
  if (!/^https?:$/.test(u.protocol)) return 'error: unsupported scheme'
  const host = u.hostname.replace(/^\[|\]$/g, '')
  let addrs
  if (net.isIP(host)) addrs = [host]
  else {
    try { addrs = (await dns.lookup(host, { all: true })).map(a => a.address) }
    catch { return 'error: could not resolve host' }
  }
  if (!addrs.length || !addrs.every(isPrivateOrLoopback)) return 'blocked: target is not an internal address'
  try {
    const resp = await fetch(u, { signal: AbortSignal.timeout(4000), redirect: 'manual' })
    const text = await resp.text()
    return `HTTP ${resp.status}\n${text.slice(0, 8000)}`
  } catch (e) { return 'error: ' + String(e.message).slice(0, 200) }
}

function isPrivateOrLoopback(ip) {
  if (ip === '0.0.0.0' || ip === '::') return true
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number)
    if (p[0] === 127 || p[0] === 10) return true
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true
    if (p[0] === 192 && p[1] === 168) return true
    if (p[0] === 169 && p[1] === 254) return true
    return false
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase()
    return l === '::1' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80') || l.startsWith('::ffff:127.') || l.startsWith('::ffff:10.')
  }
  return false
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
