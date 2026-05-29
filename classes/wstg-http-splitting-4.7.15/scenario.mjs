// WSTG-INPV-15 (4.7.15) — HTTP Splitting / Smuggling.
//
// PolyRange picks the response-splitting half of the WSTG-INPV-15 pair: a
// user-controlled value flows raw into an HTTP response header. With CRLF
// injection the attacker terminates the legitimate header block and the
// bytes that follow the original handler's later headers slide into the
// response body where the client can read them. The redirect handler emits
// an X-Internal-Token header carrying the per-deploy canary directly after
// the user-influenced header — splitting the response surfaces that token
// as the body. The request-smuggling half (CL/TE desync against a real
// proxy) is deferred — see constraints.md.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

const Path = z.string().regex(/^\/[a-z][a-z0-9_\-]*(\/[a-z][a-z0-9_\-]*)*$/, 'themed lowercase URL path')

export const Scenario = z.object({
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

  chromeInjection: ChromeInjection
    .describe('Nav link / call-to-action pointing at redirectPath so the '
      + 'feature is discoverable from the homepage chrome.'),
})
