// WSTG-INPV-05.8 — Client-Side SQL Injection.
// A search/lookup feature backed by a SQL engine that runs entirely INSIDE
// THE BROWSER (sql.js — SQLite compiled to WebAssembly). The page's inline
// JS builds the query by string concatenation against the visitor's input
// and executes it against an in-page database that the server seeded with
// a sensitive table at render time. There is no server-side database query
// — the engine, the schema, and the canary live in the browser tab.
// Recovery is via a payload that twists the concatenated query (union,
// error/like side-channel) and surfaces the seeded canary in the rendered
// results panel.
//
// Distinctness:
//   - 4.7.5.4 (server-side SQLi) puts the engine on the server and the
//     canary in a server-resident table.
//   - 4.11.1 (DOM XSS) is about HTML/JS sink execution, not query
//     construction. Here the dangerous sink is a SQL string, not innerHTML.

import { z } from 'zod'
import { Endpoint, ChromeInjection, Slot } from '../_shared/scenario-common.mjs'

const TableName = z.string().min(2).max(40).regex(/^[a-z][a-z0-9_]*$/)

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('A search / lookup / filter affordance against a small browser-resident dataset — a help-centre quick-find, an offline-capable directory, a client-side autosuggest. Fit the theme; frame it as a feature that works without round-tripping the server.'),
  endpoint: Endpoint
    .describe('GET-only landing page. The server returns a static HTML shell that boots the in-browser SQL engine.'),
  slots: z.object({ user_input: Slot })
    .describe('The injectable lookup parameter (query string is simplest). The page JS reads it on load and concatenates it into a WHERE clause executed against the in-browser DB.'),
  itemsTable: TableName
    .describe('Public catalogue table name the in-browser query targets (e.g. articles, listings, contacts).'),
  itemsPools: z.object({
    title: z.array(z.string()).min(6).describe('12-25 realistic item titles for this catalogue.'),
    body: z.array(z.string()).min(6).describe('12-25 realistic item descriptions.'),
  }).describe('Value pools used to synthesize a small public catalogue (~12 rows shipped to the browser).'),
  sensitiveTable: TableName
    .describe('A sensitive table seeded into the browser DB whose contents are visibly off-limits — staff_keys, recovery_codes, internal_tokens. Columns are fixed: id, account, secret.'),
  accountPool: z.array(z.string()).min(6)
    .describe('12-25 realistic account identifiers for the sensitive table rows (none equal to canaryAccount).'),
  secretPool: z.array(z.string()).min(6)
    .describe('12-25 realistic-looking decoy secrets — NONE may contain the canary substring.'),
  canaryAccount: z.string().min(2)
    .describe('The account whose secret IS the canary — a conventional privileged identifier (admin, root, ops, svc) the attacker can target by name during extraction.'),
  body: z.string().min(50)
    .refine(s => s.includes('{RESULTS}'), '{RESULTS} placeholder required')
    .refine(s => s.includes('{BOOT}'), '{BOOT} placeholder required')
    .describe('Page body HTML (inner). MUST contain {RESULTS} (where the rendered query output lands) and {BOOT} (where the runtime appends the sql.js boot script — do NOT write that script yourself).'),
  chromeInjection: ChromeInjection
    .describe('A discoverable affordance pointing at endpoint.path with the user_input slot wired in.'),
})
