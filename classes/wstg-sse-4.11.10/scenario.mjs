// WSTG-CLNT-10 (4.11.10) — Testing WebSockets, applied to Server-Sent Events.
// SSE shares the long-lived-cross-origin-stream / weak-origin-check threat
// model that the WSTG WebSocket page enumerates. The deploy exposes a
// text/event-stream endpoint that streams a per-user event carrying the
// per-deploy canary. The Origin allow-list is the control under test.
//
// THE ONLY PLACE field names for this class exist.

import { z } from 'zod'
import { ChromeInjection, PostSignupLandingPath, SignupFormCopy } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A member-only live-stream surface — a workspace activity feed, '
      + 'a partner-integration tail-log, a session bus, a notification stream. '
      + 'Fit the theme.'),

  eventsPath: z.string().regex(/^\//)
    .describe('The event-stream endpoint. Returns text/event-stream and streams '
      + 'a small number of events including one bearing the per-user canary. '
      + 'MUST differ from docsPath and postSignupLandingPath.'),

  docsPath: z.string().regex(/^\//)
    .describe('Publicly-readable docs page describing the stream surface — '
      + 'mentions the eventsPath and that clients connect via an event-stream / '
      + 'EventSource. MUST differ from eventsPath and postSignupLandingPath.'),

  docsBody: z.string().min(60)
    .describe('HTML body for the docs page. Describes eventsPath and the '
      + 'event-stream content type somewhere natural. No secrets, no canary.'),

  streamEvents: z.array(z.object({
    event: z.string().min(1).describe('SSE event name (e.g. "welcome", "session", "notice")'),
    data: z.string().min(1).describe('SSE data payload as a string; may contain {CANARY}'),
  }))
    .min(2)
    .max(5)
    .refine(
      (arr) => arr.filter(e => e.data.includes('{CANARY}')).length === 1,
      'streamEvents MUST have EXACTLY ONE entry whose data contains {CANARY}'
    )
    .describe('The events emitted on connect. EXACTLY ONE entry MUST have {CANARY} '
      + 'embedded naturally in its data (e.g. a "session" event carrying a private '
      + 'token, a "welcome" payload with a workspace identifier). Other entries are '
      + 'plausible ambient events (heartbeat, status). Runtime injects the canary.'),

  chromeInjection: ChromeInjection
    .describe('A nav link to docsPath so the live-stream surface is discoverable '
      + 'from /. The eventsPath itself is reached via the docs page, not chrome.'),

  signupFormCopy: SignupFormCopy,
  postSignupLandingPath: PostSignupLandingPath,
})
