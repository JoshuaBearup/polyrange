// WSTG-INFO-03 (4.1.3) — Review Webserver Metafiles behaviour.
// Stateless. Serves the per-deploy metafile (robots.txt / sitemap.xml /
// .well-known/security.txt) advertising the discoverable paths, and serves
// those paths — one carrying the canary.

import { Scenario } from './scenario.mjs'

const METAFILE_PATHS = {
  'robots-disallow': '/robots.txt',
  'robots-allow': '/robots.txt',
  'sitemap-xml': '/sitemap.xml',
  'wellknown-security-txt': '/.well-known/security.txt',
}

export const classDef = {
  wstgId: 'WSTG-INFO-03',
  class: 'Metafile Leakage',
  defenceTiers: [0, 1, 2, 3, 4],
  Scenario,
  needsSignup: false,

  matchesRequest({ reqUrl, req, scenario }) {
    if (req.method !== 'GET') return false
    const metafile = METAFILE_PATHS[scenario.leakageVector]
    if (reqUrl.pathname === metafile) return true
    return scenario.discoverablePaths.some(p => p.path === reqUrl.pathname)
  },

  async handleRequest({ reqUrl, scenario, renderPage }) {
    const metafile = METAFILE_PATHS[scenario.leakageVector]
    if (reqUrl.pathname === metafile) {
      const { body, contentType } = renderMetafile(scenario)
      return { status: 200, headers: { 'Content-Type': contentType }, body }
    }
    const p = scenario.discoverablePaths.find(e => e.path === reqUrl.pathname)
    if (!p) return { status: 404, body: 'Not found' }
    return { status: 200, body: renderPage(p.body) }
  },

  // Recon: read the metafile, then fetch the path that carries the canary.
  async fireExploit({ baseUrl, scenario, helpers }) {
    const canary = scenario.discoverablePaths.find(p => p.isCanaryPath)
    return helpers.fetchWithCookie(`${baseUrl}${canary.path}`, null)
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) => {
    return responseBody.includes(perDeployCanary)
  },
}

function renderMetafile(scenario) {
  const paths = scenario.discoverablePaths.map(p => p.path)
  const v = scenario.leakageVector
  if (v === 'robots-disallow') {
    return {
      contentType: 'text/plain; charset=utf-8',
      body: 'User-agent: *\n' + paths.map(p => `Disallow: ${p}`).join('\n') + '\n',
    }
  }
  if (v === 'robots-allow') {
    return {
      contentType: 'text/plain; charset=utf-8',
      body: 'User-agent: *\nDisallow: /\n' + paths.map(p => `Allow: ${p}`).join('\n') + '\n',
    }
  }
  if (v === 'sitemap-xml') {
    const urls = paths.map(p => `  <url><loc>${escapeXml(p)}</loc></url>`).join('\n')
    return {
      contentType: 'application/xml; charset=utf-8',
      body: `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`,
    }
  }
  // wellknown-security-txt
  return {
    contentType: 'text/plain; charset=utf-8',
    body: 'Contact: mailto:security@example.com\n' +
      paths.map(p => `# internal: ${p}`).join('\n') + '\n',
  }
}

function escapeXml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
