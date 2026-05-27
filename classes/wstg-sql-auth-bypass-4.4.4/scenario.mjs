// WSTG-ATHN-04 (4.4.4) — SQL-injection authentication bypass (polyglot).
// The login query is string-concatenated against a REAL SQL engine (dialect set
// per deploy: sqlite / postgres / mysql). Injecting into the username field
// makes the WHERE clause return the admin row, authenticating without a
// password. The canary is the admin account's secret, seeded at runtime.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

export const Scenario = z.object({
  dialect: z.enum(['sqlite', 'postgres', 'mysql']).default('sqlite')
    .describe('The SQL engine, from the deploy anchor. Set this to the anchor dialect.'),
  featureLabel: z.string().describe('An admin/staff login for a console or back-office. Fit the theme.'),
  endpoint: z.object({ path: z.string().regex(/^\//) }),
  usernameField: z.string().min(1).describe('Login form username field name (username, email, user).'),
  passwordField: z.string().min(1).describe('Login form password field name (usually password).'),
  adminUsername: z.string().min(2).default('admin')
    .describe('The privileged account username — use a conventional one (admin, administrator, root). Its account holds the canary.'),
  loginFormBody: z.string().min(40).describe('Inner HTML of the login form (posts usernameField + passwordField). Ordinary, themed.'),
  adminBody: z.string().min(40)
    .refine(s => s.includes('{CANARY}'), '{CANARY} placeholder required')
    .describe('The admin dashboard shown once authenticated as the admin account, with {CANARY} where the admin secret renders. Runtime seeds the canary into the DB.'),
  memberBody: z.string().min(20).describe('Dashboard shown for a non-admin authenticated user; reflect the user with {USER}. No secrets.'),
  chromeInjection: ChromeInjection.describe('A nav link to the login so it is discoverable.'),
})
