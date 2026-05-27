// WSTG-INPV-20 (4.7.20) — Mass Assignment.
// A profile/settings update endpoint blindly applies ALL submitted fields to
// the user's record — including a server-controlled privilege field. The
// attacker signs up (non-privileged), sees their own record on their profile,
// infers the privilege field, sets it via the update, and unlocks gated
// content carrying the canary.

import { z } from 'zod'
import { ChromeInjection, PostSignupLandingPath, SignupFormCopy } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string(),
  profilePath: z.string().regex(/^\//)
    .describe('GET page showing the signed-in user their OWN record fields (including the privilege field at its default) plus the update form. This is where the attacker infers the privilege field.'),
  profileBody: z.string().min(40)
    .refine(s => s.includes('{FIELDS}'), '{FIELDS} placeholder required')
    .describe('Inner HTML of the profile page. {FIELDS} is replaced with the user record fields rendered as a list/form. Must NOT contain the canary.'),
  updateEndpoint: z.object({
    path: z.string().regex(/^\//),
    method: z.enum(['POST', 'PUT', 'PATCH']).default('POST'),
  }).describe('The update endpoint that mass-assigns: it merges EVERY submitted JSON field into the user record with no allowlist (the sink).'),
  gatedPath: z.string().regex(/^\//)
    .describe('A privileged page that returns sensitive content ONLY when the user record has the privilege field set to the privileged value.'),
  privilegeField: z.string()
    .describe('The server-controlled field that gates access (a realistic name for this resource — role, tier, plan, access_level, account_type, etc.). NOT a generic default; fit the theme.'),
  privilegeValue: z.string()
    .describe('The value of privilegeField that unlocks gated content (e.g. admin, owner, enterprise, staff).'),
  gatedContent: z.string().min(40)
    .describe('Inner HTML returned at gatedPath to a privileged user. Embeds pr_<canary> as natural content. Never shown to non-privileged users.'),
  deniedContent: z.string().min(20)
    .describe('Inner HTML shown at gatedPath to non-privileged users (no canary) — a plausible access-denied / upgrade page.'),
  signupFormCopy: SignupFormCopy,
  signupRecordTemplate: z.record(z.string())
    .describe('Default new-user record fields. MUST include privilegeField set to a NON-privileged default (e.g. role=member). {email} substituted. No canary.'),
  postSignupLandingPath: PostSignupLandingPath,
  chromeInjection: ChromeInjection
    .describe('A nav link to /signup or the account area, themed.'),
})
