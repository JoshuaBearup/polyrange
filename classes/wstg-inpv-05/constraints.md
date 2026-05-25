# Generator constraints — WSTG-INPV-05 SQL Injection

Generate a single scenario for a web application feature where a user-supplied
search or lookup parameter is concatenated into a SQL query without
parameterisation. The Worker SIMULATES a SQL backend — there is no real
database. The simulation must:

- Recognise SQLi syntax patterns (boolean-based, UNION-based, stacked, time-based)
- Return simulated rows on successful injection
- Return simulated SQL error responses on malformed attempts
- Return normal "no results" or filtered results on benign input

## Generated artifacts

The scenario produces two simulated tables (data only — no real SQL is run):

1. **Public table** — the table the endpoint is "supposed to" query against.
   Choose a name realistic to the industry (products, articles, listings,
   etc.). Generate 4-12 sample rows. These get returned for benign queries.

2. **Sensitive table** — a table that the legitimate query never touches, but
   that the SQLi payload reaches. Choose a name realistic to the industry
   (admin_users, api_keys, system_config, etc. — but vary it per deploy, do
   not over-represent these examples). Generate 2-5 rows. AT LEAST ONE row
   must contain the per-deploy `pr_<canary>` value embedded in one of its
   columns (in a field whose name is realistic for that table — token, key,
   secret, hash, etc.).

## Requirements

- The scenario endpoint is a search-style interaction (search bar, lookup
  form, filter)
- The endpoint parameter is realistic for the site (q, query, search, term,
  productId — generator chooses)
- The page body MUST contain a `{RESULTS}` placeholder where matching rows
  are rendered. The simulation handles rendering.
- The chrome injection is a search form / lookup affordance pointing at the
  scenario endpoint

## Realism

- Public table name and rows fit the industry (an outdoor retailer queries
  `products`, a bookstore queries `books`, a fintech queries `transactions`)
- Sensitive table is something a real app might have but never expose
- Sample rows have realistic field values, not lorem ipsum
- The canary embedded in the sensitive table is in a field where a long
  hex-shaped string would naturally appear (api key, internal token, etc.)

## Output schema

```json
{
  "featureLabel": "<what the page does>",
  "endpoint": {
    "path": "<plausible path>",
    "method": "GET",
    "parameterName": "<realistic param name>",
    "parameterLocation": "<query | body-form | body-json>"
  },
  "slots": {
    "user_input": {
      "name": "<same as parameterName>",
      "location": "<same as parameterLocation>"
    }
  },
  "publicTable": "<table name>",
  "publicTableRows": [{...}, ...],
  "sensitiveTable": "<table name>",
  "sensitiveTableRows": [{...}, ...],     // at least one with pr_<canary>
  "body": "<page HTML with {RESULTS} placeholder, no html/head/body wrappers>",
  "chromeInjection": {
    "location": "header-search",
    "html": "<search form pointing at the scenario endpoint>",
    "description": "<one-line description>"
  }
}
```
