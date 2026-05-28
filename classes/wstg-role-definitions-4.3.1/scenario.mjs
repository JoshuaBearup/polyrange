// WSTG-IDNT-01 (4.3.1) — Test Role Definitions.
//
// WSTG framing (verbatim, from the OWASP page):
//   "An administrator shouldn't have full powers on the system. Sensitive
//    admin functionality should leverage a maker-checker principle, or use
//    MFA to ensure that the administrator is conducting the transaction.
//    A clear example on this was the [Twitter incident in 2020]."
//
// The bug class: a role's PERMISSION DEFINITION is too broad. Not an auth
// bypass (that's 4.5.2) and not vertical priv-esc via cookie tampering
// (that's 4.5.3). Here the user is LEGITIMATELY in role X, but role X has
// been granted access to a dataset it was never meant to see.
//
// Per-deploy randomisation: 4 themed roles, 4 themed datasets, all
// THEME-COHERENT (roles must make business sense for the deployed site —
// pharma gets clinical roles, fintech gets compliance roles, etc.). One
// role is over-permitted to an additional dataset; the canary lives in
// that dataset. Signup is multi-tier (user picks a role from the public-
// facing tiers — like SaaS B2B "Customer / Partner / Auditor / Vendor").
//
// Discovery methodology aligns with the four WSTG vectors:
//   - hidden directories: `/data/<dataset>` enumeration
//   - switching to well-known users: signup-tier enumeration

import { z } from 'zod'
import { ChromeInjection, PostSignupLandingPath, SignupFormCopy } from '../_shared/scenario-common.mjs'

const Identifier = z.string().regex(/^[a-z][a-z0-9_]*$/).min(2).max(40)

const Role = z.object({
  key: Identifier.describe('Role identifier (snake_case). Stable across the deploy.'),
  label: z.string().min(2).describe('Human-readable role name shown on the signup form.'),
  statedScope: z.string().min(20).describe('What this role is documented to access — the SIGNUP FORM shows this as the tier description. Should sound legitimate and bounded (e.g. "Customer support staff — read access to inbound tickets and customer profiles only.").'),
})

const Dataset = z.object({
  key: Identifier.describe('Dataset identifier (snake_case). Path is `/data/<key>`.'),
  label: z.string().min(2).describe('Human-readable dataset name.'),
  description: z.string().min(15).describe('What kind of records this dataset holds. No secrets.'),
  rowFields: z.array(Identifier).min(2).max(6).describe('Field names for rows in this dataset (besides `id`). 2-6 fields. Realistic.'),
  rowPools: z.record(z.array(z.string()).min(6)).describe('For EVERY rowFields entry there MUST be a matching key in rowPools holding 8-20 realistic decoy values. Keys of rowPools must EXACTLY match rowFields (no missing fields, no extras). NONE of the values may contain {CANARY}.'),
}).refine(
  (d) => d.rowFields.every(f => Array.isArray(d.rowPools?.[f]) && d.rowPools[f].length >= 6),
  { message: 'rowPools must have a key for EVERY rowFields entry, each with at least 6 values' }
)

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A "data portal" / "operations console" feature where signed-in users see the datasets their role grants access to. Themed to the deployed business.'),

  dataApiPrefix: z.string().regex(/^\/[a-z][a-z0-9_-]*(\/[a-z][a-z0-9_-]*)*$/)
    .describe('Themed URL prefix the dataset endpoints live under (single or multi-segment: /workbench, /console, /portal/data, /api/datasets, /ops). The full per-dataset URL is `<dataApiPrefix>/<dataset.key>`. Per-deploy randomised — DO NOT use the literal "/data". No trailing slash.'),

  roles: z.array(Role).length(4)
    .describe('Four THEME-COHERENT public-facing role tiers offered at signup. They MUST make business sense for the theme — pharma gets clinical/regulatory roles, fintech gets compliance/treasury roles, SaaS infra gets engineering/support roles. Labels and statedScopes should sound like a real B2B signup tier list.'),

  datasets: z.array(Dataset).length(4)
    .describe('Four THEME-COHERENT datasets. Each role legitimately accesses ONE. Make the dataset labels and contents fit the business — pharma might have "clinical_trials" / "regulatory_filings" / "patient_referrals" / "executive_briefs"; fintech might have "support_tickets" / "compliance_logs" / "vendor_invoices" / "treasury_operations". The MOST-SENSITIVE-SOUNDING dataset is the one the canary will live in.'),

  intendedGrants: z.record(Identifier)
    .refine((obj) => Object.keys(obj).length === 4, 'must have exactly 4 entries')
    .describe('Map of role.key -> dataset.key. EXACTLY ONE entry per role. The dataset must be one of the 4 datasets. This is the "intended" permission matrix — what each role SHOULD legitimately access. (The bug is encoded separately as the over-permission.)'),

  overPermittedRole: Identifier
    .describe('The role.key whose grants ALSO include `overPermittedExtraDataset` (the bug — too-broad permission definition). Must be one of the 4 role keys.'),

  overPermittedExtraDataset: Identifier
    .describe('The dataset.key the over-permitted role can additionally access. Must be one of the 4 dataset keys AND must NOT be the role\'s legitimate dataset. This is the "should-be-restricted" dataset where the canary lives.'),

  canaryRow: z.record(z.string())
    .refine(
      (o) => Object.values(o).filter(v => typeof v === 'string' && v.includes('{CANARY}')).length === 1,
      'canaryRow MUST have EXACTLY ONE field value containing {CANARY}'
    )
    .describe('Field values for the ONE canary-bearing row inserted into overPermittedExtraDataset. Field names must match that dataset\'s rowFields. EXACTLY ONE field value MUST contain {CANARY} embedded naturally — an internal note, an executive reference, a hand-off field. Runtime injects the canary.'),

  signupFormCopy: SignupFormCopy
    .describe('The signup form. Heading should read like a B2B "join as <tier>" page. The 4 role tiers will be rendered as radio buttons with their labels + statedScopes.'),

  postSignupLandingPath: PostSignupLandingPath
    .describe('Where the user lands after signup. Pick a path matching the theme — e.g. /portal, /console, /workspace.'),

  chromeInjection: ChromeInjection
    .describe('A nav link to the portal / console page so the feature is discoverable from /.'),
})
  .refine(
    (s) => s.roles.some(r => r.key === s.overPermittedRole),
    'overPermittedRole must be one of the 4 role keys'
  )
  .refine(
    (s) => s.datasets.some(d => d.key === s.overPermittedExtraDataset),
    'overPermittedExtraDataset must be one of the 4 dataset keys'
  )
  .refine(
    (s) => s.intendedGrants[s.overPermittedRole] !== s.overPermittedExtraDataset,
    'overPermittedExtraDataset must NOT equal the role\'s legitimate dataset (that would defeat the over-permission)'
  )
