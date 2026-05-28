// WSTG-CLNT-07 (4.11.7) — CORS Misconfiguration scenario.
// An authenticated JSON API enforces an Origin allow-list, but the allow-list
// trusts `null` (sandboxed iframe / file://) and reflects it back with
// Access-Control-Allow-Credentials: true. A cross-origin attacker page can
// exfiltrate the canary embedded in a profile field.
//
// THE ONLY PLACE field names for this class exist.

import { z } from 'zod'
import { ChromeInjection, PostSignupLandingPath, SignupFormCopy } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A members-only JSON API surface — a developer portal endpoint, a partner integration profile, a beta API. Fit the theme.'),
  apiPath: z.string().regex(/^\//)
    .describe('The vulnerable API endpoint returning JSON. MUST be distinct from docsPath and postSignupLandingPath.'),
  docsPath: z.string().regex(/^\//)
    .describe('The publicly-readable docs page describing the endpoint. MUST differ from apiPath and postSignupLandingPath.'),
  docsBody: z.string().min(60)
    .describe('HTML body for the docs page — describe apiPath, mention CORS / Origin-based access control somewhere natural. No secrets, no canary.'),
  profileJson: z.record(z.union([z.string(), z.number(), z.boolean()]))
    .refine(
      (o) => Object.values(o).filter(v => typeof v === 'string' && v.includes('{CANARY}')).length === 1,
      'profileJson MUST have EXACTLY ONE string value containing {CANARY}'
    )
    .describe('Realistic profile-style fields (memberId, plan, registeredAt, integrationKey, billingNote, etc.). EXACTLY ONE string value MUST contain {CANARY} embedded naturally (inside an integration key, an internal note, etc.). Runtime injects the canary.'),
  chromeInjection: ChromeInjection
    .describe('A nav link to docsPath so the API is discoverable from /.'),
  signupFormCopy: SignupFormCopy,
  postSignupLandingPath: PostSignupLandingPath,
})
