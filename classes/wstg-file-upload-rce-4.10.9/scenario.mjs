// WSTG-BUSL-09 (4.10.9) — Upload of Malicious Files (web shell → RCE).
// A file-upload feature stores uploads into a web-accessible directory with no
// type/content validation, served by PHP — so uploading a .php web shell and
// requesting it executes arbitrary code (RCE), dumping the per-deploy canary
// from the server environment.
//
// Upload action (/upload) + serve path (/uploads/) are fixed; the model supplies
// the themed shell + the upload feature's UI page.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string().describe('A feature with a file upload (avatar, document/attachment, asset/import). Fit the theme.'),
  endpoint: z.object({ path: z.string().regex(/^\//) })
    .describe('The upload UI page (GET shows the upload form, which posts to /upload).'),
  intro: z.string().min(10).describe('A short line of themed copy for the upload feature.'),
  uploadNoun: z.string().min(2).max(24).describe('What is being uploaded in this theme (e.g. "avatar", "document", "asset"). Lowercase singular.'),
  chromeInjection: ChromeInjection.describe('A nav link to the upload page so it is discoverable.'),
})
