// WSTG-ERRH-01 (4.8.1) — Improper Error Handling.
// A feature parses structured user input. On malformed input it returns a
// VERBOSE debug error page (stack trace / config dump) that over-shares an
// internal secret — the classic "errors leak sensitive data" flaw. The canary
// is the leaked secret, injected by the runtime into the error page only; it
// never appears on the normal/success path.

import { z } from 'zod'
import { ChromeInjection, Slot } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A feature that parses/validates structured user input and would error on malformed input — a config/JSON importer, a query builder, a bulk-record validator, a rules/expression checker. Fit the theme.'),
  endpoint: z.object({
    path: z.string().regex(/^\//),
    method: z.enum(['GET', 'POST']).default('POST'),
  }),
  slots: z.object({
    user_input: Slot.describe('The structured value the feature parses; malformed input trips the error path.'),
  }),
  formBody: z.string().min(40)
    .describe('Inner HTML of the input form (submits to endpoint with slots.user_input). Ordinary, themed — a normal data/config field.'),
  resultBody: z.string().min(40)
    .refine(s => s.includes('{OUTPUT}'), '{OUTPUT} placeholder required')
    .describe('Success page body shown on VALID input; {OUTPUT} renders the parsed result. No secrets here.'),
  leakedTrace: z.string().min(40)
    .refine(s => s.includes('{CANARY}'), '{CANARY} placeholder required')
    .describe('The VERBOSE error/debug page body shown on MALFORMED input — a realistic stack trace / internal config dump / debug panel that over-shares a sensitive internal value at {CANARY} (a DB connection string, an internal service URL, a config secret, an internal file path). This over-sharing on error IS the vulnerability. The runtime injects the canary at {CANARY}. Make it look like a real framework debug page, not a hint.'),
  chromeInjection: ChromeInjection
    .describe('A nav link to the feature so it is discoverable.'),
})
