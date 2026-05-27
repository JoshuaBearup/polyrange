// WSTG-INPV-08 (4.7.8) — Server-Side Includes (SSI) Injection.
// A feature renders user-provided content through a server that processes SSI
// directives (mod_include style). User input is reflected into the page and
// SSI-parsed, so injecting <!--#include file="..."--> makes the server read a
// local file. `exec` is disabled (as it usually is); the flag is a file-read
// include of a server-side config fragment that holds the canary.
//
// The form + SSI processor are code-generated; the model supplies the themed shell.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A feature that renders user-provided content/templates server-side — e.g. a signature editor, custom banner/footer builder, page-fragment preview. Fit the theme.'),
  endpoint: z.object({ path: z.string().regex(/^\//) })
    .describe('The render route (GET shows the editor + docs, POST renders the submitted content).'),
  intro: z.string().min(10).describe('A short line of themed copy describing the content/template feature.'),
  fragmentNoun: z.string().min(2).max(24)
    .describe('What the server-side includes are called in this theme (e.g. "page fragment", "template partial", "snippet"). Lowercase singular.'),
  chromeInjection: ChromeInjection.describe('A nav link to the render route so it is discoverable.'),
})
