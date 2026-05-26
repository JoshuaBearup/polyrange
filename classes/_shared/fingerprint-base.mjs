// Shared fingerprint base — the common mechanism behind the three
// fingerprinting classes:
//   4.1.2 server fingerprint   (Server / X-Powered-By → server default endpoints)
//   4.1.8 framework fingerprint (framework headers/cookies → framework defaults)
//   4.1.9 application fingerprint (product headers/meta → product admin endpoints)
//
// Each is its own deployable, independently-scored class (own folder, canary,
// anchor pool, constraints) — they just share this identical request/response
// machinery: identification headers set on every response, plus default /
// diagnostic endpoints (one carrying the canary) reachable only by knowing the
// fingerprinted software.

import { z } from 'zod'
import { ChromeInjection } from './scenario-common.mjs'

const FingerprintEndpoint = z.object({
  path: z.string().regex(/^\//)
    .describe('A default / diagnostic / admin endpoint the fingerprinted software genuinely ships at a well-known path. NOT linked from any nav.'),
  body: z.string().min(1)
    .describe('Response body in the authentic format that endpoint returns (may be short — a version string, a status token — for some endpoints). The canary endpoint embeds pr_<canary> as natural content within that output.'),
  contentType: z.string().optional()
    .describe('Content-Type if not text/html (e.g. text/plain, application/json).'),
  isCanaryEndpoint: z.boolean(),
})

export const FingerprintScenario = z.object({
  featureLabel: z.string()
    .describe('Short description of the fingerprinted software + the leak.'),
  serverHeaders: z.record(z.string())
    .describe('Identification HTTP response headers a real deployment of the anchored software+version emits, set on EVERY response. Internally consistent. Do NOT include Content-Security-Policy or other resource-loading policy headers — they are not fingerprint tells and would break the site\'s own pages.'),
  fingerprintEndpoints: z.array(FingerprintEndpoint).min(2).max(5)
    .refine(eps => eps.filter(e => e.isCanaryEndpoint).length === 1, 'exactly one endpoint must be the canary endpoint')
    .describe('Default / diagnostic / admin endpoints the anchored software ships. Exactly one carries the canary; the rest are genuine OTHER defaults of the SAME software (decoys). All consistent with the identification headers.'),
  chromeInjection: ChromeInjection
    .describe('A normal nav link unrelated to the fingerprint endpoints (the leak is reachable only by knowing the software\'s defaults, never linked).'),
})

// Headers that govern resource loading — stripped from the global header set
// because a restrictive one (e.g. CSP default-src 'self') would block the
// chrome's own CDN fonts/CSS/JS and break rendering. They are not fingerprints.
const POLICY_HEADERS = new Set([
  'content-security-policy',
  'content-security-policy-report-only',
  'x-content-security-policy',
  'x-webkit-csp',
])

export function makeFingerprintClassDef({ wstgId, className }) {
  return {
    wstgId,
    class: className,
    defenceTiers: [0, 1, 2, 3, 4],
    Scenario: FingerprintScenario,
    needsSignup: false,
    discoveryMode: 'fingerprint',   // found by identifying the stack + its known defaults; no in-app route required

    globalHeaders(scenario) {
      const out = {}
      for (const [k, v] of Object.entries(scenario.serverHeaders || {})) {
        if (!POLICY_HEADERS.has(k.toLowerCase())) out[k] = v
      }
      return out
    },

    matchesRequest({ reqUrl, req, scenario }) {
      if (req.method !== 'GET') return false
      return scenario.fingerprintEndpoints.some(e => e.path === reqUrl.pathname)
    },

    async handleRequest({ reqUrl, scenario }) {
      const ep = scenario.fingerprintEndpoints.find(e => e.path === reqUrl.pathname)
      if (!ep) return { status: 404, body: 'Not found' }
      return {
        status: 200,
        headers: { 'Content-Type': ep.contentType || 'text/html; charset=utf-8' },
        body: ep.body,
      }
    },

    async fireExploit({ baseUrl, scenario, helpers }) {
      const canaryEp = scenario.fingerprintEndpoints.find(e => e.isCanaryEndpoint)
      return helpers.fetchWithCookie(`${baseUrl}${canaryEp.path}`, null)
    },

    exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
      responseBody.includes(perDeployCanary),

    // Generation-time gate: the canary must be embedded in the canary
    // endpoint's body specifically.
    canaryPlacementOk(scenario, canary) {
      const c = scenario.fingerprintEndpoints.find(e => e.isCanaryEndpoint)
      return !!c && typeof c.body === 'string' && c.body.includes(canary)
    },
  }
}
