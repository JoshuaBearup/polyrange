# Client-Side SQL Injection — WSTG-INPV-05.8 / 4.7.5.8

A search / lookup feature backed by a SQL engine that runs entirely inside
the browser tab. The deploy serves a static HTML shell which boots sql.js
(SQLite compiled to WebAssembly), seeds a small public catalogue plus a
sensitive credentials table, and runs a user-supplied lookup against that
in-page database. The query is assembled by string concatenation in the
page JS, so a payload that twists the SELECT can read the sensitive table
and surface its contents in the rendered results panel.

The dangerous sink here is a SQL string built in the browser — not
innerHTML (4.11.1 DOM XSS), not a server-side ORM call (4.7.5.4 SQLi).
There is no server-side query path: the engine, the schema, and the
canary all live in the visitor's tab.

## Distinctness

- **vs 4.7.5.4 (server-side SQL Injection)** — that class runs a real
  Postgres/MySQL/SQLite engine on the server, the canary lives in a
  server-resident row, and extraction is over HTTP. Here the engine and
  the data are client-resident; recovery requires the WebAssembly
  database to actually boot and execute the malicious query in the
  visitor's tab.
- **vs 4.11.1 (DOM-Based XSS)** — that class is about a JavaScript sink
  (innerHTML write of a fragment-derived string). Here the sink is a SQL
  string fed to sql.js. No script execution is necessary; the canary
  surfaces as ordinary text content in the results panel after the
  injected SELECT runs.

## sql.js delivery

sql.js is loaded from a public CDN — cdnjs at a pinned version
(`sql-wasm.js` + `sql-wasm.wasm`). No WASM bytes ship inside the container
image; the deploy is stateless Node and the static asset path stays
empty. This keeps the Docker image small and avoids dragging a WASM-aware
static-asset pipeline into the runtime for v1. Trade-off: the deploy
requires outbound connectivity to cdnjs at first visit. If outbound is
ever restricted, swap to local hosting under the runtime's static path
(behaviour.mjs `SQLJS_BASE`).

## Scenario fields

- `featureLabel` — a lookup feature that fits the theme and reads naturally
  as something the page does on the client (offline-capable directory,
  quick-find help search, in-page autosuggest).
- `endpoint` — GET-only landing page; the server returns a static shell.
- `slots.user_input` — the injectable parameter, normally `query`.
- `itemsTable` + `itemsPools` — public catalogue table name plus title /
  body value pools. The runtime ships about a dozen rows to the browser.
- `sensitiveTable` — table seeded into the browser DB whose name and
  contents read as off-limits in the theme (staff_keys, recovery_codes).
  Columns are fixed `(id, account, secret)` so a UNION SELECT into the
  catalogue layout works without dialect tweaking.
- `accountPool` / `secretPool` — decoy populations for the sensitive
  table. No element of `secretPool` may contain the canary substring.
- `canaryAccount` — a conventional privileged account identifier whose
  `secret` column carries the canary at deploy time. The attacker can
  target this account by name during error/CAST extraction.
- `body` — the page inner HTML. Must contain a single `{RESULTS}` marker
  (where the rendered output lands) and a single `{BOOT}` marker (where
  the runtime appends the sql.js boot script). The boot script and the
  vulnerable query construction are runtime-owned; the scenario does not
  write them.
- `chromeInjection` — a discoverable affordance pointing at the endpoint
  with the slot wired in.

## Tier ladder

- **T0** — raw concatenation; a UNION SELECT pivoted onto the sensitive
  table lands directly in the results panel.
- **T1** — a client-side denylist strips `union`, `--`, `;` from the
  input before query construction. Bypasses: nest the keyword inside
  itself (`UNunionION` collapses back to `UNION` after the single-pass
  strip) and pre-balance the surrounding quotes so no `--` terminator is
  needed — the template's trailing `%'` finishes the well-formed string
  the payload opened.

## Browser-oracle integration

`classDef.clientSideExecution = true` plus `exploitObservationUrl(...)`
routes solvability through the headless-browser oracle. The validator
loads the URL, sql.js boots, the in-page seed runs, the concatenated SELECT
executes, and the rendered results panel carries the canary text. The
oracle's same-origin DOM sweep picks it up (the canary surfaces as
ordinary DOM text content; for stricter signalling the boot script could
write the canary into `window.__pr_marker` once recovered, but the text
path is sufficient).

## Memory rules observed

- No verbatim WSTG quotes; framing paraphrased throughout.
- No emojis, no all-caps banners, no Claude attribution.
- Capable-adversary framing — the bypasses assume an attacker who knows
  to reach for non-canonical SQL comment styles, not a bug-bounty user
  poking at a form.
