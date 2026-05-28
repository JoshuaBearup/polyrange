// WSTG-IDNT-04 (4.3.4) — Testing for Account Enumeration and Guessable User Account.
//
// WSTG verbatim:
//   "Verify if it is possible to collect a set of valid usernames by
//    interacting with the authentication mechanism of the application."
//
// Concrete vectors from the page (login response differentials):
//   - valid user + wrong password: "Login for User foo: invalid password"
//   - invalid user:                "Login failed for User foo: invalid Account"
//   Other vectors: registration reserved-name rejection, password-recovery
//   differential, 403-vs-404 URI probing, response timing, predictable
//   username patterns ("CN000100, CN000101").
//
// The class encodes the LOGIN-RESPONSE-DIFFERENTIAL form, with the
// "predictable username structure" pattern stacked on top: among ~5
// themed decoy usernames there's ONE privileged username whose
// structure carries the per-deploy canary. Submitting that username
// with any password yields the differential response — "Wrong password
// for <username>" — and the username text (containing the canary)
// surfaces in the rendered error.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A "sign in" / "login" surface where authentication differentials reveal valid usernames. Themed.'),
  endpoint: z.object({
    path: z.string().regex(/^\//),
  }),
  decoyUsernames: z.array(z.string().min(2)).min(5).max(10)
    .describe('5-10 plausible-but-NOT-valid themed usernames (e.g. for a fintech: alex.morris, kara.delacruz). The login form rejects these with the "no such account" branch. NONE may equal or contain the privileged username and NONE may contain the canary.'),
  privilegedUsername: z.string().min(4)
    .refine(s => s.includes('{CANARY}'), '{CANARY} placeholder required')
    .describe('The ONE valid privileged username. MUST contain {CANARY} embedded in its structure (e.g. "ops_intl_{CANARY}", "svc-payouts-{CANARY}", "compliance.{CANARY}@org"). Runtime substitutes the canary at deploy time — the predictable-username-structure leak per the WSTG page is the bug.'),
  validPasswordPlaceholder: z.string().min(4)
    .describe('Placeholder text for the password field shown in the form. Themed (e.g. "Use your Okta password", "Sign in with your workspace credentials").'),
  body: z.string().min(50)
    .refine(s => s.includes('{FORM}'), '{FORM} placeholder required')
    .describe('Page body HTML around the form. MUST contain {FORM} placeholder where the runtime injects the login form.'),
  chromeInjection: ChromeInjection
    .describe('A nav link to the login endpoint so it is discoverable.'),
})
