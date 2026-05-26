// WSTG-CLNT-01 (4.11.1) — DOM-Based XSS.
// Pure client-side: the served page's own JavaScript reads a DOM SOURCE
// (location.hash) and writes it to a dangerous SINK (innerHTML) with no server
// involvement — the payload sits in the URL fragment and never reaches the
// server, so server-side filtering can't see it (the whole point of DOM XSS).
// Success is confirmed by the real-browser oracle. The T1 defence is therefore
// a CLIENT-SIDE sanitizer in the page JS, not a server WAF.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A feature that legitimately renders content selected via the URL fragment — a shareable/deep-link view, a client-side router, a preview pane, a "jump to section". Fit the theme.'),
  endpoint: z.object({ path: z.string().regex(/^\//) }),
  pageBody: z.string().min(40)
    .describe('Themed inner HTML for the page (the ordinary app content). The vulnerable render widget — a container plus the JS that reads location.hash into innerHTML — is appended by the runtime, so do NOT write that script yourself. Frame the page so reading the fragment looks natural.'),
  renderLabel: z.string().min(2)
    .describe('Short heading for the fragment-rendered section, e.g. "Shared view", "Preview", "Section".'),
  chromeInjection: ChromeInjection
    .describe('A nav link to the feature so it is discoverable.'),
})
