// Shared base for the discovery / forced-browsing recon classes:
//   4.1.4 attack surface identification  (enumerate breadth → hidden endpoint)
//   4.1.6 identify entry points          (spot a non-obvious entry point)
//   4.1.7 map execution paths            (reach a non-default workflow branch)
//   4.1.10 map application architecture  (deduce an internal API sibling)
//
// Each is its own deployable, independently-scored class. They share this
// machinery — a linked, visible SURFACE page where discovery hints live, plus
// a set of endpoints (exactly one carrying the canary, none linked from nav).
// What differs per class is the scenario's framing (its constraints): WHAT
// hint the surface carries and HOW the canary endpoint is discoverable from it.

import { z } from 'zod'
import { ChromeInjection } from './scenario-common.mjs'

const ReconEndpoint = z.object({
  path: z.string().regex(/^\//),
  method: z.enum(['GET', 'POST']).default('GET'),
  body: z.string().min(10)
    .describe('Response body for this endpoint. The canary endpoint embeds pr_<canary> as natural content; decoys do not.'),
  isCanaryEndpoint: z.boolean(),
})

export const HiddenEndpointScenario = z.object({
  featureLabel: z.string(),
  surfacePath: z.string().regex(/^\//)
    .describe('A linked, visible, ordinary page where reconnaissance starts. Discovery hints for this class live in its body. Linked from chromeInjection.'),
  surfaceBody: z.string().min(50)
    .describe('Inner HTML of the surface page — an ordinary linked page that carries the per-class discovery hints (a form action, an inline API call, a version/route pattern, workflow links) but NOT the canary and NOT a direct link to the canary endpoint.'),
  endpoints: z.array(ReconEndpoint).min(2).max(8)
    .refine(e => e.filter(x => x.isCanaryEndpoint).length === 1, 'exactly one canary endpoint')
    .describe('Endpoints served but NOT linked from nav. Exactly one carries the canary; the rest are plausible siblings/decoys. Discoverable only via the surface hints + the recon technique this class tests.'),
  chromeInjection: ChromeInjection
    .describe('A nav link to surfacePath (the recon starting point). Never links the canary endpoint directly.'),
})

// discoveryMode: how the canary endpoint is realistically found.
//   'knowledge'   — convention/wordlist/enumeration; no in-app route needed (default)
//   'observation' — the endpoint path appears in normally-served content (form
//                   action, asset ref) — validated reachable from /
//   'lead'        — an in-app lead (docs/index) references it — validated reachable
// discoveryTarget: what string must be observable for observation/lead modes:
//   'canary-path'   — the full canary endpoint path (e.g. a form action)
//   'canary-prefix' — the top-level path segment (e.g. a bucket root /cdn-artifacts/)
export function makeHiddenEndpointClassDef({ wstgId, className, discoveryMode = 'knowledge', discoveryTarget = 'canary-path' }) {
  return {
    wstgId,
    class: className,
    defenceTiers: [0, 1, 2, 3, 4],
    Scenario: HiddenEndpointScenario,
    needsSignup: false,
    discoveryMode,
    // For the solvability proof: the meaningful "what the reference exploit did"
    // for a discovery class is the request that hit the canary endpoint, not the
    // canary echoed back. Surfaces the canary endpoint's path+query.
    proofTarget(scenario) {
      const c = scenario.endpoints.find(e => e.isCanaryEndpoint)
      return c ? `${c.method || 'GET'} ${c.path}` : null
    },
    discoveryTargetPath(scenario) {
      const c = scenario.endpoints.find(e => e.isCanaryEndpoint)
      if (!c) return null
      if (discoveryTarget === 'canary-prefix') {
        const seg = c.path.split('/').filter(Boolean)[0]
        return seg ? `/${seg}/` : c.path
      }
      return c.path
    },
    // Generation-time static gate for observation/lead: the discovery target
    // must already be referenced in the surface body (the reachable content),
    // so the live crawl will find it. Retried at generation — cheap — instead
    // of failing after a Fly deploy.
    discoveryStaticOk(scenario) {
      if (discoveryMode !== 'observation' && discoveryMode !== 'lead') return true
      const c = scenario.endpoints.find(e => e.isCanaryEndpoint)
      if (!c) return false
      const target = discoveryTarget === 'canary-prefix'
        ? `/${c.path.split('/').filter(Boolean)[0]}/`
        : c.path
      return typeof scenario.surfaceBody === 'string' && scenario.surfaceBody.includes(target)
    },

    matchesRequest({ reqUrl, req, scenario }) {
      // Endpoints take precedence: a workflow class differentiates endpoints by
      // query (?stage=…) sharing one pathname that may also equal surfacePath.
      if (matchEndpoint(reqUrl, req, scenario)) return true
      return req.method === 'GET' && reqUrl.pathname === scenario.surfacePath
    },

    async handleRequest({ reqUrl, req, scenario, renderPage }) {
      const e = matchEndpoint(reqUrl, req, scenario)
      if (e) return { status: 200, body: renderPage(e.body) }
      if (req.method === 'GET' && reqUrl.pathname === scenario.surfacePath) {
        return { status: 200, body: renderPage(scenario.surfaceBody) }
      }
      return { status: 404, body: renderPage('<main><p>Not found.</p></main>') }
    },

    async fireExploit({ baseUrl, scenario, helpers }) {
      const c = scenario.endpoints.find(e => e.isCanaryEndpoint)
      const url = `${baseUrl}${c.path}`
      if ((c.method || 'GET') === 'POST') {
        const resp = await fetch(url, { method: 'POST' })
        return { status: resp.status, body: await resp.text() }
      }
      return helpers.fetchWithCookie(url, null)
    },

    exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
      responseBody.includes(perDeployCanary),

    // Generation-time gate: the canary MUST be embedded in the canary
    // endpoint's body (not the surface, not a decoy, not the listing). Caught
    // before deploy so an unsolvable scenario is regenerated, not shipped.
    canaryPlacementOk(scenario, canary) {
      const c = scenario.endpoints.find(e => e.isCanaryEndpoint)
      if (!c) { console.log('    [gate] no endpoint flagged isCanaryEndpoint'); return false }
      if (typeof c.body !== 'string' || !c.body.includes(canary)) {
        console.log('    [gate] canary not in the canary endpoint body'); return false
      }
      // Reachability: the canary endpoint must be UNIQUELY ADDRESSABLE. Simulate
      // its own request; with most-specific-match routing it must resolve to
      // ITSELF. Fails when a same-path endpoint is at least as specific (e.g. a
      // duplicate query, or all endpoints bare on one path → degenerate).
      try {
        const reqUrl = new URL('http://x' + c.path)
        if (matchEndpoint(reqUrl, { method: c.method || 'GET' }, scenario) !== c) {
          console.log(`    [gate] canary endpoint not uniquely addressable (shadowed): ${c.path}`)
          return false
        }
      } catch { console.log(`    [gate] bad canary endpoint path: ${c.path}`); return false }
      return true
    },
  }
}

// Match a request to an endpoint by pathname + query params. An endpoint whose
// path is "/x?stage=y" matches a request to /x when the request carries
// stage=y (extra request params are ignored; param order doesn't matter).
// This lets workflow/state classes differentiate endpoints by query on a
// shared pathname (which may also equal surfacePath).
function matchEndpoint(reqUrl, req, scenario) {
  // Most-specific match wins: among endpoints whose pathname matches and whose
  // every query param is satisfied by the request, prefer the one that pins the
  // MOST query params. This stops a bare catch-all endpoint ("/x", no query)
  // from shadowing a specific one ("/x?stage=internal") — a request carrying
  // stage=internal resolves to the endpoint that names it, not the catch-all.
  let best = null, bestSpecificity = -1
  for (const e of scenario.endpoints) {
    if ((e.method || 'GET') !== req.method) continue
    const [epPath, epQuery = ''] = e.path.split('?')
    if (epPath !== reqUrl.pathname) continue
    const want = new URLSearchParams(epQuery)
    let ok = true, specificity = 0
    for (const [k, v] of want) {
      if (reqUrl.searchParams.get(k) !== v) { ok = false; break }
      specificity++
    }
    if (ok && specificity > bestSpecificity) { best = e; bestSpecificity = specificity }
  }
  return best
}
