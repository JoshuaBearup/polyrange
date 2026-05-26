// WSTG-INFO-05 (4.1.5) — Review Web Page Content for Information Leakage.
// The canary is leaked in the SOURCE of a normal, visible page — an HTML
// comment, a hidden input, an inline script variable, a data attribute, or a
// source-map reference — invisible when the page renders, recovered only by
// inspecting the source. Distinct from hidden-endpoint classes: the page is
// linked and ordinary; the leak is in its markup.

import { z } from 'zod'
import { Endpoint, ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('What this ordinary page is (a normal linked page on the site — homepage section, product page, dashboard widget, etc.)'),
  endpoint: Endpoint
    .describe('Path of the ordinary page that carries the source leak. It IS linked from the chrome (a normal page), unlike hidden-endpoint classes.'),
  leakVector: z.enum(['html-comment', 'hidden-input', 'inline-js-var', 'data-attribute', 'source-map-ref'])
    .describe('Where in the page SOURCE the canary hides. The deploy anchor fixes this — build the body around it.'),
  body: z.string().min(80)
    .describe('Page body HTML — inner content only, no wrappers. Renders as an ordinary page. The canary pr_<canary> is embedded in the source-only location named by leakVector (e.g. inside an HTML comment, a hidden input value, an inline JS config object, a data-* attribute, or a sourceMappingURL/comment) as natural developer content (a leftover TODO, an internal config value, a build artifact) — NOT visible when the page renders, NOT a labelled "flag".'),
  chromeInjection: ChromeInjection
    .describe('A normal nav link to this page (it is an ordinary, linked page — the leak is in its source, not in its being hidden).'),
})
