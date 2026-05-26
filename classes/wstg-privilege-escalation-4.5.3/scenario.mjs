// WSTG-ATHZ-03 (4.5.3) — Privilege Escalation.
// A logged-in normal user escalates vertically by tampering with a
// client-supplied role/profile/tier field the server trusts (the WSTG "change a
// hidden profile field from user-level to SysAdmin" technique). Normal value →
// ordinary content; the privileged value → the canary. Session-based, no DB.

import { z } from 'zod'
import { ChromeInjection, Slot } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A feature whose output is gated by the account role/tier/profile — a reports/export console, a feature-flagged dashboard, a tier-gated data view. Fit the theme.'),
  endpoint: z.object({
    path: z.string().regex(/^\//),
    method: z.enum(['GET', 'POST']).default('POST'),
  }),
  roleSlot: Slot.describe('Where the role/tier/profile value is read from the request — a body field, query param, or header the CLIENT supplies. Name it realistically (profile, role, tier, plan, account_type).'),
  normalValue: z.string().min(1)
    .describe('The non-privileged value a normal user carries (e.g. member, standard, free, user).'),
  privilegedValue: z.string().min(1)
    .describe('The value that unlocks the privileged data (e.g. admin, sysadmin, staff, enterprise). The server trusts it without re-checking against the real session role — that trust is the bug.'),
  formBody: z.string().min(40)
    .describe('The feature form (shown on GET). MUST include the role field as a value the client sends — a HIDDEN input named exactly as roleSlot.name, pre-set to normalValue (e.g. <input type="hidden" name="profile" value="member">). This is the tamperable field; do not present it as user-editable.'),
  normalBody: z.string().min(20)
    .describe('Result shown when the role is the normal value — the ordinary (non-privileged) view. No secrets.'),
  adminBody: z.string().min(40)
    .refine(s => s.includes('{CANARY}'), '{CANARY} placeholder required')
    .describe('Result shown when the role equals privilegedValue — the privileged data, with {CANARY} where a sensitive value sits. Runtime injects the canary; never put it in the scenario.'),
  chromeInjection: ChromeInjection
    .describe('A nav link to the feature so it is discoverable.'),
})
