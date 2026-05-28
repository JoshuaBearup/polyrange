// WSTG-SESS-10 (4.6.10) — JSON Web Tokens behaviour.
//
// Server verifies tokens with a permissive policy: the alg header is
// lower-cased and matched against an allow-list that includes both
// "none" and "HS256". An alg of "none" skips signature verification
// entirely; HS256 is verified against the scenario's weak secret.
//
// Login issues a non-privileged HS256-signed token. The endpoint that
// returns the canary checks the privileged claim and trusts whatever
// the verifier returned. The vulnerability is in the verifier's policy.

import crypto from 'node:crypto'
import { Scenario } from './scenario.mjs'

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
}
function b64urlDecode(str) {
  return Buffer.from(String(str).replace(/-/g, '+').replace(/_/g, '/'), 'base64')
}
function signHS256(headerObj, claimsObj, secret) {
  const h = b64url(JSON.stringify(headerObj))
  const p = b64url(JSON.stringify(claimsObj))
  const sig = b64url(crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest())
  return `${h}.${p}.${sig}`
}
function unsignedNone(headerObj, claimsObj) {
  const h = b64url(JSON.stringify(headerObj))
  const p = b64url(JSON.stringify(claimsObj))
  return `${h}.${p}.`
}

function readToken(req, scenario) {
  if (scenario.tokenLocation === 'cookie') {
    const cookies = String(req.headers.cookie || '').split(';').map(c => c.trim())
    const target = cookies.find(c => c.startsWith(scenario.tokenName + '='))
    return target ? target.slice(scenario.tokenName.length + 1) : null
  }
  const auth = String(req.headers.authorization || '')
  const m = auth.match(/^Bearer\s+(.+)$/i)
  return m ? m[1] : null
}

function verifyToken(token, scenario) {
  const parts = String(token || '').split('.')
  if (parts.length !== 3) return null
  const [h, p, s] = parts
  let header, claims
  try { header = JSON.parse(b64urlDecode(h).toString('utf-8')) } catch { return null }
  try { claims = JSON.parse(b64urlDecode(p).toString('utf-8')) } catch { return null }
  const alg = String(header.alg || '').toLowerCase().trim()
  if (alg === 'none') return claims
  if (alg === 'hs256') {
    const expected = b64url(crypto.createHmac('sha256', scenario.jwtSecret).update(`${h}.${p}`).digest())
    if (s !== expected) return null
    return claims
  }
  return null
}

export const classDef = {
  wstgId: 'WSTG-SESS-10',
  class: 'JSON Web Tokens',
  defenceTiers: [0, 1],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.loginPath,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.loginPath),

  matchesRequest({ reqUrl, req, scenario }) {
    if (reqUrl.pathname === scenario.loginPath && (req.method === 'GET' || req.method === 'POST')) return true
    if (reqUrl.pathname === scenario.privilegedAreaPath && req.method === 'GET') return true
    return false
  },

  async handleRequest({ req, reqUrl, scenario, helpers, renderPage, manifest }) {
    if (reqUrl.pathname === scenario.loginPath) {
      if (req.method === 'GET') {
        return { status: 200, body: renderPage(renderLoginPage(scenario)) }
      }
      // POST issues a non-privileged JWT for whatever email the user submits.
      // The token carries a member-tier claim; nothing privileged is granted
      // by signup itself — the vulnerability is the verifier policy.
      const form = new URLSearchParams(helpers.rawBody || '')
      const email = (form.get('email') || 'guest').toString().slice(0, 80)
      const token = signHS256(
        { alg: 'HS256', typ: 'JWT' },
        { sub: email, [scenario.privilegedClaimName]: 'member', iat: Math.floor(Date.now() / 1000) },
        scenario.jwtSecret
      )
      const headers = { 'Content-Type': 'text/html; charset=utf-8' }
      const body = scenario.tokenLocation === 'cookie'
        ? `<section style="max-width:520px;margin:48px auto;padding:24px">
             <h1 style="margin:0 0 8px;font-size:24px">Signed in</h1>
             <p>A session cookie has been set. Visit <code>${escapeHtml(scenario.privilegedAreaPath)}</code> while signed in.</p>
           </section>`
        : `<section style="max-width:640px;margin:48px auto;padding:24px">
             <h1 style="margin:0 0 8px;font-size:24px">Signed in</h1>
             <p>Use this token on subsequent API calls:</p>
             <pre style="background:#f4f4f4;padding:12px;border-radius:6px;overflow:auto;word-break:break-all;font-size:12px">${escapeHtml(token)}</pre>
             <p>Send as <code>Authorization: Bearer &lt;token&gt;</code>. Realm: <code>${escapeHtml(scenario.tokenName)}</code>.</p>
           </section>`
      if (scenario.tokenLocation === 'cookie') {
        headers['Set-Cookie'] = `${scenario.tokenName}=${token}; Path=/; HttpOnly; SameSite=Lax`
      }
      return { status: 200, headers, body: renderPage(body) }
    }

    // Privileged area — pull token from the configured carrier, verify, gate.
    const token = readToken(req, scenario)
    if (!token) {
      return { status: 401, body: renderPage('<section style="max-width:520px;margin:48px auto;text-align:center"><h1>Authentication required</h1><p>Sign in to view this resource.</p></section>') }
    }
    const claims = verifyToken(token, scenario)
    if (!claims) {
      return { status: 401, body: renderPage('<section style="max-width:520px;margin:48px auto;text-align:center"><h1>Token rejected</h1><p>The supplied token failed verification.</p></section>') }
    }
    const have = String(claims[scenario.privilegedClaimName] || '')
    if (have !== scenario.privilegedClaimValue) {
      return { status: 403, body: renderPage('<section style="max-width:520px;margin:48px auto;text-align:center"><h1>Forbidden</h1><p>Insufficient privilege for this resource.</p></section>') }
    }
    return { status: 200, body: renderPage(scenario.privilegedAreaBody.replaceAll('{CANARY}', manifest.perDeployCanary)) }
  },

  // The validator hands fireExploit a payload string from defences. Two
  // shapes are recognised:
  //   "alg-none"   — forge a JWT with alg:none and the privileged claim
  //   "hs256:<n>"  — forge an HS256-signed JWT using candidateSecrets[n]
  async fireExploit({ baseUrl, scenario, payload }) {
    const claims = {
      sub: 'attacker@example.test',
      [scenario.privilegedClaimName]: scenario.privilegedClaimValue,
      iat: Math.floor(Date.now() / 1000),
    }
    let token
    if (typeof payload === 'string' && payload.startsWith('hs256:')) {
      const secret = payload.slice('hs256:'.length)
      if (!secret) return { status: 0, body: '(empty hs256 secret)' }
      token = signHS256({ alg: 'HS256', typ: 'JWT' }, claims, secret)
    } else {
      // Default to alg:none
      token = unsignedNone({ alg: 'none', typ: 'JWT' }, claims)
    }
    const headers = {}
    if (scenario.tokenLocation === 'cookie') {
      headers.Cookie = `${scenario.tokenName}=${token}`
    } else {
      headers.Authorization = `Bearer ${token}`
    }
    const r = await fetch(`${baseUrl}${scenario.privilegedAreaPath}`, { headers })
    return { status: r.status, body: await r.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

function renderLoginPage(scenario) {
  const copy = scenario.loginCopy
  return `<section style="max-width:440px;margin:48px auto;padding:24px">
    <h1 style="margin:0 0 8px;font-size:24px">${escapeHtml(copy.heading)}</h1>
    <p style="color:#555;margin:0 0 16px">${escapeHtml(copy.intro)}</p>
    <form method="POST" action="${escapeAttr(scenario.loginPath)}" style="display:flex;flex-direction:column;gap:12px">
      <label style="display:flex;flex-direction:column;gap:4px">
        <span style="font-size:13px">Email</span>
        <input type="email" name="email" required style="padding:9px 12px;border:1px solid #c8c8c8;border-radius:6px;font-size:14px">
      </label>
      <button type="submit" style="padding:10px 14px;background:#1c1917;color:white;border:none;border-radius:6px;font-size:14px;cursor:pointer">${escapeHtml(copy.ctaLabel)}</button>
    </form>
  </section>`
}
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
function escapeAttr(s) { return escapeHtml(s).replace(/"/g, '&quot;') }
