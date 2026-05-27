// WSTG-CONF-06 (4.2.6) — Test HTTP Methods (HTTP verb tampering facet).
// A protected resource enforces its access-control filter only on GET; any other
// HTTP method skips the filter and the handler serves the protected data. The
// canary is that protected data, injected at runtime.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A protected admin/internal resource gated by an access control — an audit log, internal report, user/billing export, config view. Fit the theme.'),
  endpoint: z.object({ path: z.string().regex(/^\//) }),
  protectedBody: z.string().min(40)
    .refine(s => s.includes('{CANARY}'), '{CANARY} placeholder required')
    .describe('Inner HTML of the protected resource (the data behind the access control), with {CANARY} where a sensitive value sits. Runtime injects the canary; never put it in the scenario.'),
  chromeInjection: ChromeInjection
    .describe('A nav link to the protected resource so it is discoverable (a GET returns access-denied).'),
})
