// WSTG-INPV-07 (4.7.7) — XML Injection / XML External Entity (XXE), file read.
// A themed feature accepts an XML document and parses it with external entities
// enabled (real libxml2 via libxmljs2). A DOCTYPE that declares an external
// SYSTEM entity pointing at a local file is resolved and reflected back — so an
// attacker reads a server-side file holding the canary.
//
// The endpoint + XML parsing are code-generated; the model supplies only the
// themed shell. The canary file path is fixed/hinted server-side.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A feature that ingests XML — e.g. a record/feed/config IMPORT, an XML API, a sitemap/RSS submitter, a document preview. Fit the theme.'),
  endpoint: z.object({ path: z.string().regex(/^\//) })
    .describe('The XML-ingest route (GET shows docs + a submit form, POST parses the submitted XML).'),
  importIntro: z.string().min(10)
    .describe('A short line of themed copy describing the XML import/preview feature.'),
  recordNoun: z.string().min(2).max(24)
    .describe('What the imported XML represents in this theme (e.g. "order", "article", "contact", "asset"). Lowercase singular.'),
  chromeInjection: ChromeInjection
    .describe('A nav link to the XML-ingest route so it is discoverable.'),
})
