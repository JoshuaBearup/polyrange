// WSTG-INPV-05.4 — PostgreSQL SQL Injection scenario schema.
// THE ONLY PLACE field names for this class exist.

import { z } from 'zod'
import { Endpoint, ChromeInjection, Slot, PostSignupLandingPath, SignupFormCopy } from '../_shared/scenario-common.mjs'

const PgTableName = z.string().min(2).max(40).regex(/^[a-z][a-z0-9_]*$/)

export const Scenario = z.object({
  featureLabel: z.string(),
  endpoint: Endpoint,
  slots: z.object({
    user_input: Slot,
  }),
  primaryTable: PgTableName
    .describe('Postgres table the legitimate search query touches — what a real implementation of this feature on this site would name it'),
  primaryFieldPools: z.record(z.array(z.string()).min(6))
    .describe('For EACH field a primary-table row has, a pool of at least 6 (ideally 12-25) realistic varied values. The deploy pipeline samples these to synthesize a realistic population of rows. Field names match what this resource genuinely stores.'),
  primaryTableRows: z.array(z.record(z.union([z.string(), z.number()]))).optional()
    .describe('SYNTHESIZED by the deploy pipeline from primaryFieldPools. Do NOT generate this yourself.'),
  sensitiveTable: PgTableName
    .describe('Postgres table reached only via SQLi — something a real implementation of this site would have but never expose, named per the site\'s conventions'),
  sensitiveFieldPools: z.record(z.array(z.string()).min(6))
    .describe('For EACH field a sensitive-table row has, a pool of at least 6 realistic varied values. The deploy pipeline samples these to synthesize the sensitive population. NONE of these values may contain the canary.'),
  sensitiveCanaryFields: z.record(z.string())
    .describe('Field values for the ONE sensitive row carrying the canary (same field names as sensitiveFieldPools). Exactly one field value MUST contain pr_<canary>, in a field where a long token-shaped string would naturally appear (key, token, secret, hash).'),
  sensitiveTableRows: z.array(z.record(z.union([z.string(), z.number()]))).optional()
    .describe('SYNTHESIZED by the deploy pipeline from sensitiveFieldPools + sensitiveCanaryFields. Do NOT generate this yourself.'),
  body: z.string().min(50)
    .refine(s => s.includes('{RESULTS}'), '{RESULTS} placeholder is required')
    .describe('Page body HTML — inner content only. Must contain {RESULTS} placeholder where rendered rows go.'),
  chromeInjection: ChromeInjection
    .describe('Search affordance in the chrome — a search bar or filter link that submits to scenario.endpoint.path with slots.user_input as the param name. This is how the search feature is discoverable to anyone (signed in or not) browsing the site.'),
  signupFormCopy: SignupFormCopy,
  signupRecordTemplate: z.record(z.string())
    .describe('Initial field values for a newly-signed-up user\'s row in the primary table. The {email} token in any value will be substituted with the signed-up email.'),
  postSignupLandingPath: PostSignupLandingPath,
})
