# Weak or Unenforced Username Policy — WSTG-IDNT-05 / 4.3.5

## WSTG scope

OWASP officially MERGED this test into WSTG-IDNT-04 (Account Enumeration)
"due to overlapping scope related to predictable username structures and
enumeration techniques." The PolyRange framework keeps 4.3.5 atomic — the
two underlying surfaces are distinct:

- **4.3.4** — the LOGIN endpoint leaks which usernames exist (response
  differential)
- **4.3.5** — the SIGNUP endpoint ACCEPTS usernames it shouldn't, and
  the app then treats the registered identity as a privileged one
  downstream (typically via normalisation that the signup filter missed)

Residual page content kept the surface description:

> "Predictable username structures... weak enforcement mechanisms
> allowing easy account discovery... username format patterns that
> reveal information about valid accounts."

## How the class encodes this

A SaaS-style signup accepts any submitted username — no reserved-name
list, no normalisation-equivalence check. The portal's identity check
NORMALISES the submitted username (case-fold / whitespace-trim / NFKC)
and compares against an internal reserved name. A user who signs up
with a name that NORMALISES TO the reserved name is treated as that
privileged identity and gets the canary-bearing portal body.

Three concrete collision vectors the LLM picks one of per deploy:

- `case-fold` — submit `ADMIN` / `AdMiN`; server lower-cases for lookup
- `whitespace-trim` — submit ` admin ` (leading/trailing spaces); trim
- `unicode-nfkc` — submit `ＡＤＭＩＮ` (fullwidth / homoglyph); NFKC-fold

## Scenario fields

- `featureLabel`: SaaS / community / portal sign-up + member area.
- `reservedInternalName`: the privileged name the app treats specially
  (admin / system / support / root). Lowercase.
- `collisionVector`: which normalisation slip the bug is. Picked by the
  LLM per deploy from `case-fold` / `whitespace-trim` / `unicode-nfkc`.
- `memberPortalPath`: the post-signup portal (also serves as the
  postSignupLandingPath).
- `privilegedPortalBody`: HTML returned when the signed-in user's
  NORMALISED username equals the reserved name. MUST contain `{CANARY}`.
- `memberPortalBody`: ordinary member view. Use `{USERNAME}` for
  personalisation. No secrets.
- `signupFormCopy`: themed copy. MUST NOT mention reserved-name
  restrictions (the bug is the absence of that check at signup).
- `chromeInjection`: nav link to /signup.

Distinct from related atomics:
- **4.3.4 Account Enumeration** — login differential (separate surface).
- **4.5.3 Privilege Escalation** — no cookie tampering or role switch;
  the user is legitimately authenticated under their own session, but
  their CHOSEN USERNAME slips through normalisation to the reserved
  identity.
- **4.3.2 Registration** — that class tests register-as-trusted-role
  via mass-assignment of role/account_type. Here the field tampered is
  the USERNAME, and the exploit is normalisation collision rather than
  mass-assignment.
