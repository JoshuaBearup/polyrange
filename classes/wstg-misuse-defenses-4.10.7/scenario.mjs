// WSTG-BUSL-07 (4.10.7) — Test Defenses Against Application Misuse.
// Verbatim WSTG framing: "If the application does not respond in any way
// and the attacker can continue to abuse functionality and submit clearly
// malicious content at the application, the application has failed this
// test case."
//
// The class implements an inquiry/search-style endpoint that never reacts
// defensively (no rate-limit, no lockout, no block, no payload filter)
// against obviously-malicious traffic. A server-side global counter
// increments on each abusive-pattern submission (SQLi shapes, `<script`,
// `../`, OR 1=1, …). When the counter crosses a threshold, the app
// continues to serve and surfaces an internal "diagnostic queue" view —
// a notice a defended app would never produce because the abuse would
// have been blocked / throttled / locked out long before the threshold.
// The canary lives in that diagnostic view.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A user-facing input feature (inquiry intake, search, lookup, request form) where sustained obviously-malicious traffic should provoke a defensive response. Fit the theme.'),
  endpoint: z.object({
    path: z.string().regex(/^\//),
    queryParamName: z.string().min(1)
      .describe('Name of the user-submitted free-text parameter (q, query, search, term, inquiry — what a real team would call it).'),
  }),
  abuseThreshold: z.number().int().min(3).max(8)
    .describe('Number of obviously-malicious submissions the app accepts before exposing the diagnostic queue. 3-8: low enough to be CTF-recoverable, high enough that ONE attack does not trigger it (the test is sustained-abuse).'),
  formBody: z.string().min(60)
    .refine(s => s.includes('{INPUT}'), '{INPUT} placeholder required')
    .describe('HTML around the input form. {INPUT} is replaced with the form control. Frame as a normal user-facing feature; the bug is operational (no defenses), not in the HTML.'),
  normalResponseBody: z.string().min(40)
    .refine(s => s.includes('{QUERY}'), '{QUERY} placeholder required')
    .describe('Response for a non-abusive submission. Use {QUERY} to echo the submitted value. No secrets.'),
  diagnosticBody: z.string().min(40)
    .refine(s => s.includes('{CANARY}'), '{CANARY} placeholder required')
    .describe('"Internal diagnostic queue" response returned once the abuse counter has crossed the threshold. MUST contain {CANARY} embedded naturally — a queue-dump entry, an internal triage note, a hand-off reference. Framed as a notice a real SOC would normally see only after sustained abuse a defended app would have blocked.'),
  chromeInjection: ChromeInjection
    .describe('A nav link to the feature so it is discoverable.'),
})
