// WSTG-ATHZ-02 (4.5.2) — Bypassing Authorization Schema.
// A privileged endpoint enforces AUTHENTICATION (must be logged in) but not
// AUTHORIZATION (no role check). Any signed-up normal user who reaches it gets
// the privileged data. The admin route is hidden from the rendered UI but is
// present in the nav source (a client-side-only role gate) — the discovery
// lead. The canary is the privileged data, injected by the runtime on the
// authorised-but-not-authenticated... i.e. served to any authenticated session.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A privileged/admin-only function a real app would gate behind a role — an audit log, a billing/export console, a user-management or internal-report page. Fit the theme.'),
  adminEndpoint: z.object({
    path: z.string().regex(/^\//)
      .describe('The privileged endpoint path. Use a plausible admin/internal path (e.g. /admin/audit-log, /internal/billing/export, /console/users).'),
    method: z.enum(['GET', 'POST']).default('GET'),
  }),
  adminBody: z.string().min(40)
    .refine(s => s.includes('{CANARY}'), '{CANARY} placeholder required')
    .describe('Inner HTML of the privileged page — the admin/internal data a normal user must never see. Contains {CANARY} where a sensitive privileged value sits (an internal record, a secret config row). The runtime injects the canary; do NOT put the canary value here.'),
  chromeInjection: ChromeInjection
    .describe('The site nav. MUST contain a link to adminEndpoint.path that is HIDDEN from normal users in the rendered view (e.g. a role-gated/hidden nav item — style="display:none" or a data-role="admin" item) but present in the source. This client-side-only gate is the discovery lead: the link is in source for everyone, the server endpoint just fails to re-check the role.'),
})
