// WSTG-INPV-11 (4.7.11) — Code Injection (polyglot).
// A feature that evaluates a user-supplied expression in a REAL language
// runtime (a formula/metric/rule/template field). The eval runs in a
// self-contained backend app in scenario.language; the Node front proxies the
// (WAF-filtered) request to it. The per-deploy canary lives in the backend
// process's environment; the attacker injects code that reads it.

import { z } from 'zod'
import { ChromeInjection, Slot } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  // Set from the per-deploy language anchor. Selects which real interpreter
  // backend runs the eval and which WAF rule set / payloads apply.
  language: z.enum(['python', 'php', 'ruby', 'node']).default('python')
    .describe('The server-side language whose runtime evaluates the input. Use the language given in the DEPLOY ANCHOR.'),
  featureLabel: z.string()
    .describe('A feature that legitimately evaluates a user expression server-side — a formula/metric builder, a custom pricing or scoring rule, a report-field expression, a calculator. Must fit the theme and the language.'),
  endpoint: z.object({
    path: z.string().regex(/^\//),
    method: z.enum(['GET', 'POST']).default('POST'),
  }).describe('The endpoint that evaluates the expression (the sink).'),
  slots: z.object({
    user_input: Slot.describe('The parameter whose value is evaluated as code (the injection point).'),
  }),
  resultBody: z.string().min(40)
    .refine(s => s.includes('{OUTPUT}'), '{OUTPUT} placeholder required')
    .describe('Page body HTML — inner content only. Must contain {OUTPUT} where the evaluation result is rendered.'),
  formBody: z.string().min(40)
    .describe('Inner HTML hosting the input form that submits to the endpoint with slots.user_input. Ordinary, themed — a normal expression/formula field, no hint that arbitrary code runs.'),
  secretEnvName: z.string().regex(/^[A-Z][A-Z0-9_]*$/)
    .describe('An environment-variable name a real deployment would have (e.g. DB_PASSWORD, API_TOKEN, SIGNING_KEY). The per-deploy canary is injected into the backend process env under this name; the attacker recovers it by injecting code that reads the environment. NO canary value here — just the name.'),
  chromeInjection: ChromeInjection
    .describe('A nav link to the tool/feature so it is discoverable.'),
})
