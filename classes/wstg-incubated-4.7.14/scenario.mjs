// WSTG-INPV-14 (4.7.14) — Incubated Vulnerability.
// Two-step flow: submit a report (incubation) → view the report (trigger).
// The view-step appends an "automatic admin reply" whenever the submitted
// category matches a privileged internal value. The privileged value's name
// leaks via a stale dev comment in the submit form. The admin reply carries
// the canary.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A submit-and-track flow: a user files something (a bug report, a tip, a request) and later visits a per-item page to see status / replies. Fit the theme.'),
  submitFormPath: z.string().regex(/^\//)
    .describe('Submit form path (GET = form, POST = create). MUST differ from viewPathTemplate.'),
  viewPathTemplate: z.string().regex(/[:{]id[}]?/)
    .describe('Per-report viewer path template containing :id or {id} (e.g. "/reports/:id"). MUST differ from submitFormPath.'),
  categoryFieldName: z.string().min(1)
    .describe('Name of the category form field a real product would use (category, type, area, queue).'),
  messageFieldName: z.string().min(1)
    .describe('Name of the free-text message field (message, body, details, summary).'),
  visibleCategories: z.array(z.string().min(1)).min(2).max(5)
    .describe('2-5 public category values surfaced by the form. Themed. None may equal triggerCategory.'),
  triggerCategory: z.string().min(2)
    .describe('Internal/privileged category value NOT shown by the form. Distinct from visibleCategories. The view step appends the admin reply when a stored report carries this value.'),
  hintText: z.string().min(20)
    .describe('Stale-looking comment text the submit form embeds. MUST contain {TRIGGER} (substituted with triggerCategory). Phrase as a dev TODO: "TODO: remove the {TRIGGER} option before public launch — internal triage only."'),
  submitFormBody: z.string().min(60)
    .refine(s => s.includes('{OPTIONS}') && s.includes('{HINT}'),
      'submitFormBody must include {OPTIONS} and {HINT}')
    .describe('HTML around the form (heading, intro, structure). {OPTIONS} substituted with the public category radios, {HINT} substituted with the leaked dev comment.'),
  reportRenderBody: z.string().min(40)
    .refine(s => s.includes('{MESSAGE}') && s.includes('{CATEGORY}') && s.includes('{ADMIN_REPLY}'),
      'reportRenderBody must include {MESSAGE}, {CATEGORY}, and {ADMIN_REPLY}')
    .describe('HTML for the per-report viewer. {MESSAGE} substituted with the submitted message; {CATEGORY} with the category; {ADMIN_REPLY} with the admin reply (empty for normal categories, populated for trigger).'),
  adminReplyBody: z.string().min(40)
    .refine(s => s.includes('{CANARY}'), '{CANARY} placeholder required')
    .describe('HTML appended to the report view when the stored category equals triggerCategory. {CANARY} substituted; embed naturally — an internal escalation reference, a hand-off note, an audit-log fragment.'),
  chromeInjection: ChromeInjection
    .describe('A nav link to submitFormPath so the submit flow is discoverable.'),
})
