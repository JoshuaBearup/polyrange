// WSTG-BUSL-08 (4.10.8) — Upload of Unexpected File Types (Content-Type bypass).
// An image-upload feature validates the CLIENT-SUPPLIED Content-Type header
// (weak) rather than the real content. Spoofing Content-Type: image/png while
// uploading a .php bypasses the filter; php -S then executes the unexpected
// file (RCE), dumping the canary.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string().describe('A feature with an IMAGE upload (avatar/photo/banner). Fit the theme.'),
  endpoint: z.object({ path: z.string().regex(/^\//) }).describe('The upload UI page (GET form posting to /upload).'),
  intro: z.string().min(10).describe('A short line of themed copy for the image-upload feature.'),
  imageNoun: z.string().min(2).max(24).describe('What image is being uploaded (e.g. "avatar", "photo", "banner"). Lowercase singular.'),
  chromeInjection: ChromeInjection.describe('A nav link to the upload page so it is discoverable.'),
})
