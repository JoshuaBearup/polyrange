// WSTG-INPV-02 (4.7.2) — Stored / Persistent XSS.
// User-submitted content is stored and later rendered UNESCAPED to viewers.
// The attacker submits a payload carrying the canary; viewing the page renders
// it unescaped (in a real browser it executes). Two-step: submit, then view.

import { z } from 'zod'
import { ChromeInjection, Slot } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('The submit-and-display feature (comment thread, product review, guestbook, profile bio, support note — fits the theme).'),
  submitEndpoint: z.object({
    path: z.string().regex(/^\//),
    method: z.enum(['POST']).default('POST'),
  }).describe('Where content is submitted (POST).'),
  viewPath: z.string().regex(/^\//)
    .describe('Page that renders all stored submissions UNESCAPED (may equal a GET of the submit path).'),
  slots: z.object({
    user_input: Slot.describe('The submitted field — location body-form or body-json; the stored-then-reflected value.'),
  }),
  submitFormBody: z.string().min(40)
    .describe('Inner HTML of the page hosting the submit form (the form POSTs to submitEndpoint with the user_input field). Ordinary content.'),
  viewBody: z.string().min(40)
    .refine(s => s.includes('{ITEMS}'), '{ITEMS} placeholder required')
    .describe('Inner HTML of the view page. Must contain {ITEMS} where stored submissions are rendered UNESCAPED, one after another.'),
  itemTemplate: z.string().min(2)
    .refine(s => s.includes('{VALUE}'), '{VALUE} placeholder required')
    .describe('HTML wrapper for a single stored submission, with {VALUE} where the raw stored value is interpolated UNESCAPED (this is the stored-XSS sink).'),
  chromeInjection: ChromeInjection
    .describe('A nav link to the submit/view feature so it is discoverable.'),
})
