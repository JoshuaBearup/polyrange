// WSTG-CLNT-03 (4.11.3) — Testing for HTML Injection.
// User input is rendered into the page WITHOUT HTML encoding. An attacker
// can inject arbitrary HTML elements that the browser renders as part of
// the DOM — modifying the page content seen by the victim. Distinct from
// XSS (no JS execution required); the test is about UNESCAPED HTML
// rendering. The success oracle is a real browser confirming an injected
// element with text content matching the canary appears in the rendered
// DOM (proves the HTML rendered, not just that the substring is in the
// raw source).

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A user-facing feature where text input appears unescaped on a page (a search-result echo, a greeting, a "did you mean?" prompt). The page MUST be reachable via a GET URL carrying the input — this is browser-oracle-required.'),
  endpoint: z.object({
    path: z.string().min(1).describe('URL path the scenario lives at'),
    method: z.literal('GET').describe('GET-only: the browser oracle navigates to a URL with the payload in the slot'),
  }),
  slots: z.object({
    user_input: z.object({
      name: z.string().describe('Parameter name a real product would use for this feature (q / search / term / name — themed).'),
      location: z.enum(['query', 'path-segment'])
        .describe('Browser-oracle constraint: must be query or path-segment so the validator can load a single GET URL with the payload.'),
    }),
  }),
  body: z.string().min(50)
    .refine(s => (s.match(/\{INPUT\}/g) || []).length === 1, '{INPUT} placeholder must appear exactly once')
    .describe('Page body HTML — inner content only. MUST contain exactly one {INPUT} placeholder in an HTML body text context (between tags, not inside an attribute, not inside a <script>). The user-supplied value is substituted there UNESCAPED.'),
  chromeInjection: ChromeInjection,
})
