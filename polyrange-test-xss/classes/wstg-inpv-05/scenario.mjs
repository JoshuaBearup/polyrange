// WSTG-INPV-05 — SQL Injection scenario schema.
// THE ONLY PLACE field names for this class exist.

import { z } from 'zod'
import { Endpoint, ChromeInjection, Slot } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string(),
  endpoint: Endpoint,
  slots: z.object({
    user_input: Slot,
  }),
  publicTable: z.string().describe('Name of the table the legitimate query touches (products, articles, listings, etc.)'),
  publicTableRows: z.array(z.record(z.union([z.string(), z.number()]))).min(4).max(12),
  sensitiveTable: z.string().describe('Name of the table reached only via SQLi (admin_users, api_keys, system_config, etc.)'),
  sensitiveTableRows: z.array(z.record(z.union([z.string(), z.number()]))).min(2).max(5)
    .describe('Rows of the sensitive table. AT LEAST ONE row must contain pr_<canary> in one of its column values.'),
  body: z.string().min(50)
    .refine(s => s.includes('{RESULTS}'), '{RESULTS} placeholder is required')
    .describe('Page body HTML — inner content only. Must contain {RESULTS} placeholder where rendered rows go.'),
  chromeInjection: ChromeInjection,
})
