# PostgreSQL SQL Injection — WSTG-INPV-05.4 / section 4.7.5.4

Generate a feature where a user-supplied search/lookup parameter is
concatenated into a SQL query without parameterisation, exposing the
database to UNION-based injection.

## Feature shape

- A search/filter/lookup interaction on a primary resource — the kind
  of feature that fits the theme's industry and vibe
- The user-controlled string lands in a WHERE clause via concatenation
- A second table exists in the schema whose contents are clearly sensitive
  in the context of this site's industry — the kind of thing whose leak
  would be the headline of the breach
- Both tables must support a `UNION SELECT *` (compatible column arity)

## Generated artifacts (synthesized — you provide pools, not rows)

The deploy pipeline synthesizes large realistic populations for both tables
(primary ~150–1000 rows, sensitive ~15–60 rows) by sampling your pools — a
real DB has hundreds of rows, not a handful. You provide:

- `primaryTable` (name) + `primaryFieldPools` — for each field a primary row
  has, a pool of 12–25 realistic varied values
- `sensitiveTable` (name) + `sensitiveFieldPools` — pools for the sensitive
  table's fields (none may contain the canary)
- `sensitiveCanaryFields` — the ONE sensitive row carrying `pr_<canary>`,
  embedded in a field where a long token-shaped value naturally appears
  (key, token, secret, hash)

Both tables share the `(id, owner_session, data)` shape so `UNION SELECT
id, owner_session, data FROM <sensitive>` works. Provide value pools (lists
of possible values per field) plus the single canary row — do NOT write out
the full list of individual rows; the deploy pipeline synthesizes those from
your pools.

## Request shape

- `slots.user_input.location` — where the injectable parameter arrives
- `slots.user_input.name` — the parameter name a real implementation
  of this feature on this site would use, derived from the theme

## chromeInjection

A search affordance in the chrome that points at the scenario endpoint —
appropriate for the feature shape (e.g. a header search bar if the
feature is a search; an inline filter link if the feature is a filter).
