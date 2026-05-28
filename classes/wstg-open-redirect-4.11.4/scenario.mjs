// WSTG-CLNT-04 (4.11.4) — Client-side URL Redirect (open redirect).
// A static page's inline JS reads a redirect-target parameter and assigns it to
// location.href with NO validation — so an attacker-controlled URL sends the
// browser off-site. Confirmed by the real-browser oracle observing an off-origin
// navigation carrying the canary marker (attacker-supplied).

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string().describe('A page that redirects the user onward — e.g. a post-login return, a "leaving the site" interstitial, a link tracker. Fit the theme.'),
  endpoint: z.object({ path: z.string().regex(/^\//) }).describe('The redirect page route.'),
  redirectParam: z.string().min(2).max(20).regex(/^[a-z_][a-z0-9_]*$/)
    .describe('The redirect-target query parameter — a CONVENTIONAL one: next, return, returnUrl, url, redirect, dest, continue, to.'),
  pageBody: z.string().min(40).describe('Themed page body HTML (e.g. a "redirecting you now…" message). Inner content only.'),
  chromeInjection: ChromeInjection.describe('A nav link to the redirect page so it is discoverable.'),
})
