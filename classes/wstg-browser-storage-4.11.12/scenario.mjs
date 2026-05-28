// WSTG-CLNT-12 (4.11.12) — Testing Browser Storage.
// Sensitive data is improperly stored in client-side storage (localStorage /
// sessionStorage) where any same-origin script can read it. WSTG framing:
// "authentication tokens (e.g., JWTs) stored in localStorage or
// sessionStorage, which are accessible via JavaScript".
//
// The class encodes this as: an "onboarding" / "embed init" page that
// accepts an integration token via URL param and `localStorage.setItem`s
// it under a themed key. The token IS the canary. Loading the page in a
// browser persists it to localStorage where the oracle's localStorage scan
// finds it.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A page that accepts a token / API key / integration secret via URL parameter and persists it to localStorage for later use. Realistic real-world anti-pattern (widget loaders, partner portal bootstrap). Themed.'),
  endpoint: z.object({
    path: z.string().min(1),
    method: z.literal('GET'),
  }),
  slots: z.object({
    user_input: z.object({
      name: z.string().describe('Query parameter name carrying the token (token, key, integration, init — themed).'),
      location: z.literal('query'),
    }),
  }),
  storageKey: z.string().regex(/^[A-Za-z][A-Za-z0-9_-]*$/)
    .describe('localStorage key the page stores the token under. Themed identifier (e.g. partner_token, integration_key, embed_secret).'),
  body: z.string().min(50)
    .describe('Page body HTML. No special placeholder needed. Describe the integration / init purpose so the page reads as a real config endpoint.'),
  chromeInjection: ChromeInjection,
})
