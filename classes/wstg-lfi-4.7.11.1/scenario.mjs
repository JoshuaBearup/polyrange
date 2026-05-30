// WSTG-INPV-11.1 (4.7.11.1) — Local File Inclusion (PHP php://filter).
// A page-include feature passes a user-controlled name straight to PHP include()
// (real PHP backend). The canary lives in a PHP CONFIG file, so a plain include
// just EXECUTES it (no output) — the attacker must use the php://filter wrapper
// (convert.base64-encode) to exfiltrate the file's SOURCE. Distinct from plain
// path-traversal file read (WSTG-ATHZ-01): this is inclusion → wrapper exfil.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string().describe('A site/CMS with a dynamic page-include feature (renders sections by name). Fit the theme.'),
  endpoint: z.object({ path: z.string().regex(/^\//) })
    .describe('The page route; a query parameter selects which page/section to include.'),
  pageParam: z.string().min(2).max(20).regex(/^[a-z_][a-z0-9_]*$/)
    .describe('The include parameter name. Pick what a real product team would name it for this site\'s page-include feature given the theme — the noun the feature actually represents. Avoid generic placeholders (q, search, find, filter, lookup); pick a name rooted in the feature\'s domain vocabulary.'),
  intro: z.string().min(10).describe('A short line of themed copy for the page host.'),
  chromeInjection: ChromeInjection.describe('A nav link to the page route so it is discoverable.'),
})
