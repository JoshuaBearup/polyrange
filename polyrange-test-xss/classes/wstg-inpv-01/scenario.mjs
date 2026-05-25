// WSTG-INPV-01 — Reflected XSS scenario schema.
// THE ONLY PLACE field names for this class exist.

import { z } from 'zod'
import { Endpoint, ChromeInjection, Slot } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string().describe('Short description of what the page does'),
  endpoint: Endpoint,
  slots: z.object({
    user_input: Slot.describe('Where user-controlled input enters the page'),
  }),
  body: z.string().min(50)
    .refine(s => (s.match(/\{INPUT\}/g) || []).length === 1, '{INPUT} placeholder must appear exactly once')
    .describe('Page body HTML — inner content only, no <html>/<head>/<body> wrappers. Must contain exactly one {INPUT} placeholder in an executable reflection context (HTML body text, HTML attribute, JavaScript string, HTML comment).'),
  chromeInjection: ChromeInjection,
})
