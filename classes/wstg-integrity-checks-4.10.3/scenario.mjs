// WSTG-BUSL-03 (4.10.3) — Integrity Checks.
// A redemption flow accepts a token shaped like `<base64-payload>.<signature>`
// (looks signed). The server reads the payload but NEVER verifies the
// signature. The user is shown a default token whose payload says
// `sku=<defaultSku>`; the privileged response is gated on `sku=<privilegedSku>`.
// Forging a token whose payload swaps the sku (with any garbage signature)
// recovers the canary.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A redemption/activation flow taking a "signed" token — voucher redeemer, gift-card activator, license verifier, promo unlocker. Fit the theme.'),
  endpoint: z.object({
    path: z.string().regex(/^\//),
    tokenParamName: z.string().min(1)
      .describe('Name of the token form field (token, voucher, license, code, key — what a real team would call it).'),
  }),
  defaultSku: z.string().min(2)
    .describe('SKU/tier baked into the default token shown to the user (basic, starter, trial, public). NOT the privileged value.'),
  privilegedSku: z.string().min(2)
    .describe('SKU/tier the privileged response is gated on. Distinct from defaultSku. The default token never carries this — the user must forge it.'),
  defaultPayloadExtras: z.record(z.union([z.string(), z.number(), z.boolean()]))
    .describe('Additional JSON fields baked into the default token payload alongside sku (customer, email, issuedAt). Realistic, themed; no secrets.'),
  formBody: z.string().min(40)
    .refine(s => s.includes('{TOKEN}'), '{TOKEN} placeholder required in formBody')
    .describe('HTML around the redemption form. {TOKEN} is replaced with an input pre-filled with the default token so the user can read it.'),
  normalResponseBody: z.string().min(40)
    .describe('Response for default-sku redemption. Use {SKU} for the redeemed sku. No secrets.'),
  privilegedResponseBody: z.string().min(40)
    .refine(s => s.includes('{CANARY}'), '{CANARY} placeholder required')
    .describe('Response for privileged-sku redemption. {CANARY} embedded naturally (an activation key, a download URL fragment).'),
  chromeInjection: ChromeInjection
    .describe('A nav link to the redemption endpoint so it is discoverable.'),
})
