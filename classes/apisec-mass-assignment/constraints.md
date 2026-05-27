# Mass Assignment — WSTG-INPV-20 / 4.7.20

Generate an authenticated app where a profile/settings UPDATE endpoint blindly
applies every submitted field to the user record, including a server-controlled
privilege field the user should never set.

## Flow this tests
1. Sign up (non-privileged). The new record's `privilegeField` is at its safe default.
2. The profile page shows the user their own record (so the privilege field is
   inferable — e.g. they see `role: member`).
3. The update endpoint mass-assigns: the attacker submits the privilege field
   set to the privileged value.
4. The gated page now returns its sensitive content (the canary).

## Key fields
- `privilegeField` / `privilegeValue`: realistic for the resource (role/tier/
  plan/account_type → admin/owner/enterprise/staff). Fit the theme; don't default.
- `signupRecordTemplate`: includes `privilegeField` at a NON-privileged default. No canary.
- `gatedContent`: holds `pr_<canary>` as natural privileged content. `deniedContent`: no canary.
- `profileBody`: ordinary; `{FIELDS}` renders the record. No canary.
