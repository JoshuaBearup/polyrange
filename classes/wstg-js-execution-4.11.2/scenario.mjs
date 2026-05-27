// WSTG-CLNT-02 (4.11.2) — JavaScript Execution.
// A subtype of client-side XSS distinguished by the SINK: user input flows into
// a direct JS-execution sink (eval) rather than an HTML sink. The page JS reads
// a query parameter and eval()s it; the payload is raw JavaScript. Success is
// confirmed by the real-browser oracle. T1 is a client-side keyword filter on
// the eval input (a server WAF is irrelevant — execution is client-side).

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A feature that evaluates a user-supplied EXPRESSION client-side in JavaScript — an inline calculator/formula field, a client-side rule/condition evaluator, a quick-compute box. Fit the theme.'),
  endpoint: z.object({ path: z.string().regex(/^\//) }),
  paramName: z.string().min(1)
    .describe('The query parameter whose value the page JS evaluates (e.g. expr, formula, calc, q, eq).'),
  pageBody: z.string().min(40)
    .describe('Themed inner HTML (ordinary app content). The runtime appends the vulnerable widget (reads the query param and eval()s it); do NOT write that script. Frame the page so evaluating an expression client-side looks natural.'),
  renderLabel: z.string().min(2)
    .describe('Short heading for the result section, e.g. "Result", "Computed".'),
  chromeInjection: ChromeInjection
    .describe('A nav link to the feature so it is discoverable.'),
})
