// WSTG-CRYP-04 (4.9.4) — Weak Encryption behaviour.
// The auth cookie is AES-256-CBC(JSON.stringify({user})) base64url-encoded. The
// key + IV are generated fresh per process (per deploy) and HARDCODED into the
// JS bundle the app serves — a "secret committed to client source" bug. Reading
// the bundle hands the attacker the key, so they forge an admin auth cookie.

import crypto from 'node:crypto'
import { Scenario } from './scenario.mjs'

const ALG = 'aes-256-cbc'
// Per-deploy (per-process) key material. Random => unmemorisable across deploys,
// but the SAME values are embedded in the served JS and used by the server.
const KEY = crypto.randomBytes(32)
const IV = crypto.randomBytes(16)

function encryptAuth(obj) {
  const c = crypto.createCipheriv(ALG, KEY, IV)
  return Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]).toString('base64url')
}
function decryptAuth(token) {
  try {
    const d = crypto.createDecipheriv(ALG, KEY, IV)
    const out = Buffer.concat([d.update(Buffer.from(String(token), 'base64url')), d.final()]).toString('utf8')
    return JSON.parse(out)
  } catch { return null }
}

function bundleJs() {
  // Realistic client bundle that leaks the key/IV/algorithm/format.
  return `// session.js — client session helper (bundled by build)
"use strict";
var SESSION_ALG = "${ALG}";
var SESSION_KEY = "${KEY.toString('hex')}"; // 256-bit key
var SESSION_IV  = "${IV.toString('hex')}";  // 128-bit IV
// The "auth" cookie is base64url( AES-256-CBC( JSON.stringify({ user }) ) ).
function buildAuthCookie(user) {
  var crypto = require("crypto");
  var c = crypto.createCipheriv(SESSION_ALG, Buffer.from(SESSION_KEY, "hex"), Buffer.from(SESSION_IV, "hex"));
  return Buffer.concat([c.update(JSON.stringify({ user: user }), "utf8"), c.final()]).toString("base64url");
}
`
}

function getCookie(req, name) {
  const c = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='))
  return c ? c.slice(name.length + 1) : null
}

export const classDef = {
  wstgId: 'WSTG-CRYP-04',
  class: 'Weak Encryption',
  defenceTiers: [0],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.basePath,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.basePath),

  matchesRequest({ reqUrl, scenario }) {
    return reqUrl.pathname === scenario.basePath || reqUrl.pathname === scenario.jsPath
  },

  async handleRequest({ req, reqUrl, scenario, renderPage, manifest }) {
    // Serve the JS bundle (with the hardcoded key).
    if (reqUrl.pathname === scenario.jsPath) {
      return { status: 200, headers: { 'Content-Type': 'application/javascript; charset=utf-8' }, body: bundleJs() }
    }

    const script = `\n<script src="${scenario.jsPath}"></script>`
    const auth = getCookie(req, 'auth')

    // First visit (no cookie): issue an encrypted guest session so the format
    // is discoverable by decrypting it with the leaked key.
    if (!auth) {
      const token = encryptAuth({ user: 'guest' })
      const body = renderPage(scenario.memberBody.replaceAll('{USER}', 'guest') + script)
      return {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'Set-Cookie': `auth=${token}; Path=/` },
        body,
      }
    }

    const claims = decryptAuth(auth)
    const user = claims && typeof claims.user === 'string' ? claims.user : 'guest'
    if (user === scenario.adminUsername) {
      return { status: 200, body: renderPage(scenario.adminBody.replace('{CANARY}', manifest.perDeployCanary) + script) }
    }
    return { status: 200, body: renderPage(scenario.memberBody.replaceAll('{USER}', escapeHtml(user)) + script) }
  },

  // Reference exploit: read the JS bundle, recover key+IV, forge an auth cookie
  // for the admin account, then read the dashboard canary.
  async fireExploit({ baseUrl, scenario, payload, helpers }) {
    const jsText = await (await fetch(`${baseUrl}${scenario.jsPath}`)).text()
    const keyHex = (jsText.match(/SESSION_KEY\s*=\s*"([0-9a-fA-F]{64})"/) || [])[1]
    const ivHex = (jsText.match(/SESSION_IV\s*=\s*"([0-9a-fA-F]{32})"/) || [])[1]
    if (!keyHex || !ivHex) return { status: 0, body: '' }
    const c = crypto.createCipheriv(ALG, Buffer.from(keyHex, 'hex'), Buffer.from(ivHex, 'hex'))
    const forged = Buffer.concat([
      c.update(JSON.stringify({ user: String(payload) }), 'utf8'), c.final(),
    ]).toString('base64url')
    return helpers.fetchWithCookie(`${baseUrl}${scenario.basePath}`, `auth=${forged}`)
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
