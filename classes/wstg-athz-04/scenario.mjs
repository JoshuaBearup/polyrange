// WSTG-ATHZ-04 — IDOR scenario schema.
// THE ONLY PLACE field names for this class exist.

import { z } from 'zod'
import { ChromeInjection, Slot } from '../_shared/scenario-common.mjs'

const IDOREndpoint = z.object({
  path: z.string().min(1).describe('URL path — if identifier is path-segment, include {id} or :id placeholder'),
  method: z.enum(['GET', 'POST']).default('GET'),
  identifierLocation: z.enum(['path-segment', 'query', 'body-json'])
    .describe('Where the requested resource identifier appears'),
  identifierName: z.string().describe('Realistic param/field name for the identifier (id, ref, account_id, etc.)'),
})

const PrincipalRecord = z.object({
  identifier: z.union([z.string(), z.number()]).describe('Identifier value matching the chosen scheme'),
  ownerSessionId: z.string().describe('Session token that legitimately owns this record'),
  fields: z.record(z.string()).describe('Record fields visible when this principal is viewed'),
  isCanaryRecord: z.boolean().describe('True for exactly ONE record — that record must contain pr_<canary> in one of its fields'),
})

export const Scenario = z.object({
  featureLabel: z.string(),
  endpoint: IDOREndpoint,
  slots: z.object({
    user_input: Slot,
  }),
  identifierScheme: z.enum(['sequential-integer', 'uuid', 'base62', 'slug'])
    .describe('Naming convention for identifiers across principal records'),
  principalRecords: z.array(PrincipalRecord).min(4).max(8)
    .refine(rs => rs.filter(r => r.isCanaryRecord).length === 1, 'exactly one record must be marked isCanaryRecord'),
  defaultSession: z.string().describe('Which sessionId the headless browser is logged in as — MUST NOT own the canary record'),
  body: z.string().min(50)
    .refine(s => s.includes('{RECORD_DETAILS}'), '{RECORD_DETAILS} placeholder is required')
    .describe('Page body HTML — inner content only. Must contain {RECORD_DETAILS} placeholder where the looked-up record is rendered.'),
  chromeInjection: ChromeInjection,
})
