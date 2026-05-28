// WSTG-IDNT-03 (4.3.3) — Test Account Provisioning Process.
//
// WSTG verbatim:
//   "The provisioning of accounts presents an opportunity for an attacker
//    to create a valid account without application of the proper
//    identification and authorization process."
//   "Can an administrator or other user provision accounts with privileges
//    greater than their own?"
//
// The bug: an "invite teammate" / "add user" endpoint trusts the caller
// to specify the invitee's role, with no check that the caller is allowed
// to grant that role. Any authenticated user (customer tier) can invite
// themself a new admin-tier account. Distinct from 4.3.1 (role-grants too
// broad on legitimate roles) and 4.5.2 (auth check fails). Here auth works
// and roles are correctly scoped — the PROVISIONING endpoint is the bug.

import { z } from 'zod'
import { ChromeInjection, PostSignupLandingPath, SignupFormCopy } from '../_shared/scenario-common.mjs'

const Identifier = z.string().regex(/^[a-z][a-z0-9_]*$/).min(2).max(40)

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A SaaS "teammate management" / "user administration" surface where authenticated users can invite new members. Themed.'),

  customerRoleKey: Identifier
    .describe('The role key new public-signup users get by default. Themed (customer, member, viewer, contributor).'),
  adminRoleKey: Identifier
    .describe('The privileged role key. Distinct from customerRoleKey. Themed (admin, owner, workspace_admin, manager).'),
  customerRoleLabel: z.string().min(2)
    .describe('Human-readable label for customer role, themed.'),
  adminRoleLabel: z.string().min(2)
    .describe('Human-readable label for admin role, themed.'),

  invitePath: z.string().regex(/^\//)
    .describe('Path of the invite-teammate endpoint (POST). Themed (/team/invite, /workspace/members/add, /people/invite).'),
  inviteFormPath: z.string().regex(/^\//)
    .describe('Path of the invite form (GET — renders the form, accessible to any authed user). MUST differ from invitePath if you want a separate GET form path, OR match invitePath (the form posts back to itself).'),
  adminDataPath: z.string().regex(/^\//)
    .describe('Path of the admin-only endpoint that returns the canary. MUST start with /. Properly admin-gated by the runtime (NOT the bug).'),
  loginPath: z.string().regex(/^\//)
    .describe('Path of the sign-in endpoint (GET = render form, POST = submit). Themed per-deploy (per the framework\'s deploy-time surface randomisation rule). MUST differ from /signup, inviteFormPath, invitePath, and adminDataPath.'),

  inviteFormCopy: z.object({
    heading: z.string().describe('Themed heading for the invite form'),
    intro: z.string().describe('Short intro paragraph explaining the feature'),
    ctaLabel: z.string().describe('Submit button label'),
  }).describe('Copy for the invite-teammate form'),

  adminDataBody: z.string().min(40)
    .refine(s => s.includes('{CANARY}'), '{CANARY} placeholder required')
    .describe('HTML body returned by adminDataPath when accessed by an admin user. MUST contain {CANARY} embedded naturally — an internal note, a workspace token, an audit reference. Runtime injects the canary.'),

  signupFormCopy: SignupFormCopy,
  postSignupLandingPath: PostSignupLandingPath
    .describe('Where the user lands after public signup (which always assigns customerRoleKey).'),

  chromeInjection: ChromeInjection
    .describe('A nav link to inviteFormPath so the provisioning surface is discoverable.'),
})
  .refine(
    (s) => s.customerRoleKey !== s.adminRoleKey,
    'customerRoleKey and adminRoleKey must differ'
  )
  .refine(
    (s) => s.adminDataPath !== s.invitePath && s.adminDataPath !== s.inviteFormPath,
    'adminDataPath must differ from invitePath and inviteFormPath'
  )
