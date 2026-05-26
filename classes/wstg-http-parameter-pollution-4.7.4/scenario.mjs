// WSTG-INPV-04 (4.7.4) — HTTP Parameter Pollution.
// The classic filter/backend parsing mismatch: a request filter inspects the
// FIRST occurrence of a duplicated parameter, while the backend uses the LAST.
// At T1 the filter blocks the privileged value; the bypass sends it twice
// (allowed-first, privileged-last) so the filter passes the safe value but the
// backend acts on the privileged one — recovering the canary.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A feature that selects a view/dataset/scope by a parameter — a report viewer, data export with a scope selector, a dashboard mode switch. Fit the theme.'),
  endpoint: z.object({
    path: z.string().regex(/^\//),
    method: z.enum(['GET', 'POST']).default('GET'),
  }),
  paramName: z.string().min(1)
    .describe('The parameter subject to pollution (realistic: view, report, mode, dataset, scope, channel).'),
  allowedValue: z.string().min(1)
    .describe('A benign value the filter permits and the backend treats as the ordinary view (e.g. summary, public, standard).'),
  restrictedValue: z.string().min(1)
    .describe('The privileged value that makes the backend return the sensitive data; the T1 filter blocks this exact value when it is the FIRST occurrence. A plausible privileged option (internal, admin, all, raw, full).'),
  normalBody: z.string().min(20)
    .refine((s) => true, '')
    .describe('Ordinary result for allowedValue. SHOULD present the available options INCLUDING the restricted one (e.g. a view selector listing it) so the privileged option is observable. No secrets.'),
  adminBody: z.string().min(40)
    .refine((s) => s.includes('{CANARY}'), '{CANARY} placeholder required')
    .describe('Result when the backend resolves the restricted value — the privileged data with {CANARY}. Runtime injects the canary; never put it in the scenario.'),
  chromeInjection: ChromeInjection
    .describe('A nav link to the feature so it is discoverable.'),
})
