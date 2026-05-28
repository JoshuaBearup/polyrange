// WSTG-BUSL-02 (4.10.2) — Ability to Forge Requests.
// A submit form accepts a categorical field (priority / department / queue).
// The UI exposes only "normal" public options, but the server also recognises
// a privileged value never surfaced by the UI. The privileged value's name
// leaks via a stale-looking HTML comment inside the form ("TODO: hide
// internal_audit from public form before launch") — a realistic dev slip.
// Forging a POST with that field set to the privileged value returns the
// internal response containing the canary.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A user-facing submit form — support ticket, contact, request, feedback — that routes by a categorical field. Fit the theme.'),
  endpoint: z.object({
    path: z.string().regex(/^\//),
    fieldName: z.string().min(1).describe('Name of the routing field (priority, category, department, queue, tier — what a real team would call it).'),
  }),
  visibleOptions: z.array(z.string().min(1)).min(2).max(5)
    .describe('Values the UI exposes (e.g. ["question", "feedback", "bug"]). Realistic and themed; none of these may equal privilegedOption.'),
  privilegedOption: z.string().min(1)
    .describe('A privileged routing value NOT shown by the UI (internal_audit, executive_brief, vip, ops_escalation, security_review). Themed; distinct from every visibleOptions entry.'),
  hiddenHint: z.string().min(20)
    .describe('A stale-looking HTML comment string the form embeds. Reading carefully reveals the privileged option exists. MUST contain {PRIVILEGED}, which the runtime replaces with privilegedOption at render. Phrase like a real dev TODO ("TODO: hide {PRIVILEGED} option from public form before launch").'),
  formBody: z.string().min(60)
    .refine(s => s.includes('{OPTIONS}') && s.includes('{HINT}'),
      'formBody must include {OPTIONS} and {HINT}')
    .describe('HTML around the form fields. {OPTIONS} is replaced with the UI control for visibleOptions; {HINT} is replaced with the leaked dev comment.'),
  normalResponseBody: z.string().min(40)
    .describe('Response shown for any visibleOptions submission. Use {VALUE} where the submitted value should appear. No secrets.'),
  privilegedResponseBody: z.string().min(40)
    .refine(s => s.includes('{CANARY}'), '{CANARY} placeholder required')
    .describe('Response shown when the privileged routing value is accepted. {CANARY} is substituted with the per-deploy canary; embed it naturally (an internal reference, a hand-off note).'),
  chromeInjection: ChromeInjection
    .describe('A nav link to endpoint.path so the form is discoverable.'),
})
