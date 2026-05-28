// WSTG-IDNT-05 (4.3.5) — Testing for Weak or Unenforced Username Policy.
//
// OWASP has officially merged WSTG-IDNT-05 into WSTG-IDNT-04. The framework
// KEEPS them atomic — the underlying surfaces are distinct: 4.3.4 is about
// the LOGIN endpoint leaking which usernames exist (response differential);
// 4.3.5 is about the SIGNUP endpoint ACCEPTING usernames it shouldn't, and
// the app then treating that registered identity as a privileged one
// downstream.
//
// Pre-merge scope (residual content from the current WSTG page):
//   "Predictable username structures... weak enforcement mechanisms
//    allowing easy account discovery... username format patterns that
//    reveal information about valid accounts."
//
// The class encodes the bug via the canonical real-world failure mode:
// signup accepts a name that the app downstream treats as having
// privileged identity (case-folding / whitespace / Unicode-normalisation
// collision with a reserved internal account name). Registering that
// name grants the privileged role; that role's portal returns the canary.

import { z } from 'zod'
import { ChromeInjection, PostSignupLandingPath, SignupFormCopy } from '../_shared/scenario-common.mjs'

const Identifier = z.string().regex(/^[a-z][a-z0-9_]*$/).min(2).max(40)

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A SaaS / community / portal sign-up + member area, where the app downstream treats a normalised-equivalent of an internal reserved name as the same identity. Themed.'),

  reservedInternalName: z.string().min(3)
    .describe('The internal reserved name the app treats as privileged (e.g. "admin", "system", "support"). Lowercase.'),

  // The realistic real-world failure: user submits a name that, after
  // normalisation (case-fold, trim, NFKC), equals the reserved name. The
  // form's input filter MISSES this — typical bug.
  collisionVector: z.enum(['case-fold', 'whitespace-trim', 'unicode-nfkc'])
    .describe('How the policy is bypassed:\n - case-fold: signup accepts "Admin" / "ADMIN" / "AdMiN"; server case-folds for lookup, treats as the reserved name\n - whitespace-trim: signup accepts " admin " (leading/trailing spaces); server trims for lookup\n - unicode-nfkc: signup accepts homoglyphs ("аdmin" Cyrillic a, "ad\\u017Cin", "ⓐdmin"); server NFKC-normalises'),

  memberPortalPath: z.string().regex(/^\//)
    .describe('Path of the post-signup member portal (also serves as postSignupLandingPath). The portal renders different content for the privileged identity vs ordinary members.'),

  privilegedPortalBody: z.string().min(40)
    .refine(s => s.includes('{CANARY}'), '{CANARY} placeholder required')
    .describe('HTML body returned when the signed-in user\'s normalised username == reservedInternalName. MUST contain {CANARY}; embed naturally — an internal note, an admin-only metric, an audit reference. Runtime injects the canary.'),

  memberPortalBody: z.string().min(40)
    .describe('Ordinary member portal HTML — what regular users see. No secrets. Use {USERNAME} for the user\'s submitted username (echoed back for personalisation).'),

  signupFormCopy: SignupFormCopy
    .describe('Themed signup copy. Heading like "Create your <theme> account". Should NOT mention reserved-name restrictions (the bug is the absence of that check).'),
  postSignupLandingPath: PostSignupLandingPath,

  chromeInjection: ChromeInjection
    .describe('A nav link to /signup so the surface is discoverable.'),
})
