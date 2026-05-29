// WSTG-INPV-15 (4.7.15) — HTTP Splitting / Smuggling.
//
// PolyRange covers both halves of WSTG-INPV-15 across two infra variants
// chosen per deploy:
//
//   splitting — a user-controlled value flows raw into an HTTP response
//               header. CRLF injection terminates the legitimate header
//               block; trailing headers (including a per-deploy X-Internal-
//               Token carrying the canary) slide into the response body
//               where the client reads them back.
//
//   smuggling — an HAProxy frontend and a raw-net Node backend disagree on
//               how to delimit a request body when Content-Length and
//               Transfer-Encoding are both present. A CL.TE payload causes
//               HAProxy to forward bytes the backend interprets as a
//               second request — and because that second request inherits
//               the frontend-added trusted-upstream header from the first
//               request's headers, an access-controlled admin endpoint
//               returns its canary-bearing response to the smuggled query.
//
// The two halves share themed surface fields (the splitting endpoints are
// always part of the rendered chrome; the smuggling endpoints add a
// privileged admin canary route reachable only via desync). The per-deploy
// infraVariant anchor pins which Dockerfile the build picks.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

const Path = z.string().regex(/^\/[a-z][a-z0-9_\-]*(\/[a-z][a-z0-9_\-]*)*$/, 'themed lowercase URL path')

export const Scenario = z.object({
  infraVariant: z.enum(['splitting', 'smuggling']).default('splitting')
    .describe('Per-deploy infra half — pinned by the deploy anchor. '
      + '"splitting" runs the response-splitting half on a single-process '
      + 'Node deploy. "smuggling" runs the CL/TE desync half on an HAProxy '
      + 'frontend in front of a raw-net Node backend.'),

  featureLabel: z.string()
    .describe('Theme-coherent label for the redirect / preferences surface '
      + '(e.g. "Link tracker", "Outbound redirect", "Profile preferences"). '
      + 'Used in chrome copy.'),

  redirectPath: Path
    .describe('Themed redirect route (e.g. /go, /out, /track, /jump). '
      + 'Accepts GET with a destination query parameter and emits an HTTP '
      + '302 whose Location header is built from that parameter.'),

  redirectParam: z.string().regex(/^[a-z_][a-z0-9_]{1,18}$/)
    .describe('Conventional redirect-target parameter name (e.g. next, '
      + 'return, to, dest, url). Per-deploy randomised. Lowercase, '
      + 'identifier-style, 2 to 19 chars.'),

  redirectPageBody: z.string().min(60)
    .describe('Themed HTML body shown when the redirect route is hit '
      + 'without the destination parameter — a brief copy block '
      + 'explaining what the route does, fit to the site theme. Inner '
      + 'content only.'),

  prefPath: Path
    .describe('Themed user-preferences route (e.g. /set-pref, /prefs, '
      + '/save-preference). Accepts GET with `name` and `value` query '
      + 'parameters and emits an HTTP 200 whose Set-Cookie header is '
      + 'built from name and value.'),

  prefNameParam: z.string().regex(/^[a-z_][a-z0-9_]{1,18}$/)
    .describe('Query parameter name for the preference key (e.g. name, '
      + 'key, pref, field). Distinct from prefValueParam.'),

  prefValueParam: z.string().regex(/^[a-z_][a-z0-9_]{1,18}$/)
    .describe('Query parameter name for the preference value (e.g. '
      + 'value, v, data, setting). Distinct from prefNameParam.'),

  prefPageBody: z.string().min(60)
    .describe('Themed HTML body shown on the preferences route confirmation. '
      + 'Inner content only.'),

  internalTokenHeader: z.string()
    .regex(/^X-[A-Z][A-Za-z0-9\-]{4,30}$/, 'PascalCase-hyphen header name starting with X-')
    .describe('Internal-mesh header name the redirect handler emits on '
      + 'every response (e.g. X-Internal-Token, X-Mesh-Auth, X-Edge-Sig). '
      + 'Carries the per-deploy canary value. The split response surfaces '
      + 'this header as body bytes.'),

  // ── Smuggling-only fields ───────────────────────────────────────────────
  // These are always present in the schema but only consulted by the
  // smuggling variant. Themed paths/headers keep the surface coherent.

  adminCanaryPath: Path
    .describe('Themed internal admin route (e.g. /admin/health, /internal/'
      + 'status, /ops/sigcheck). Only reachable through the desync path: '
      + 'the backend returns the per-deploy canary on requests that arrive '
      + 'carrying the frontend-added trusted-upstream header. Direct '
      + 'unsmuggled requests reach the backend without that header (the '
      + 'frontend strips inbound copies) and get rejected.'),

  adminPageBody: z.string().min(40)
    .describe('Themed HTML the admin route returns to authorised requests. '
      + 'Inner content only. Must include the literal token "{CANARY}" — '
      + 'the runtime substitutes the per-deploy canary in.')
    .refine(s => s.includes('{CANARY}'), '{CANARY} placeholder required'),

  trustedUpstreamHeader: z.string()
    .regex(/^X-[A-Z][A-Za-z0-9\-]{4,30}$/, 'PascalCase-hyphen header name starting with X-')
    .describe('Frontend-added header name the backend treats as proof of '
      + 'a trusted upstream (e.g. X-Trusted-Upstream, X-Edge-Forwarded, '
      + 'X-Gateway-Auth). HAProxy sets this on every inbound request and '
      + 'strips any client-supplied copy. The smuggled second request '
      + 'inherits this header from the first request because the backend '
      + 'parses it as a body-continuation, not a new request.'),

  trustedUpstreamValue: z.string().regex(/^[a-z][a-z0-9\-]{2,30}$/)
    .describe('Sentinel string the backend compares the trusted-upstream '
      + 'header against (e.g. haproxy-edge, gateway-prod, edge-01). '
      + 'Lowercase identifier-style, 3 to 31 chars.'),

  chromeInjection: ChromeInjection
    .describe('Nav link / call-to-action pointing at redirectPath so the '
      + 'feature is discoverable from the homepage chrome.'),
})
