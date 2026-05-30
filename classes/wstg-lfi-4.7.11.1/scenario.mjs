// WSTG-INPV-11.1 (4.7.11.1) — Local File Inclusion (PHP php://filter).
// A dynamic-include feature passes a user-controlled name straight to PHP
// include() (real PHP backend). The canary lives in a PHP CONFIG file, so a
// plain include just EXECUTES it (no output) — the attacker must use the
// php://filter wrapper (convert.base64-encode) to exfiltrate the file's
// SOURCE. Distinct from plain path-traversal file read (WSTG-ATHZ-01):
// inclusion → wrapper exfil.

import { z } from 'zod'
import { ChromeInjection, Slot } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string().describe('A dynamic-include feature on this site. The shape (and the noun the parameter represents) follow from the theme.'),
  endpoint: z.object({ path: z.string().regex(/^\//) })
    .describe('The page route hosting the dynamic include.'),
  slots: z.object({
    user_input: Slot,
  }).describe('The include parameter. The deploy anchor seeds slots.user_input.location — build the feature around whatever position is seeded.'),
  intro: z.string().min(10).describe('A short line of themed copy for the page host.'),
  chromeInjection: ChromeInjection.describe('A nav link to the page route so it is discoverable.'),
})
