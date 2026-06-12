# PolyRange Attack Trace — design spec

Status: draft for review. Version 1.0.0 of the schema.
Purpose: turn PolyRange from a binary solve/no-solve benchmark into one that can also analyse *how* each agent attacked — its reasoning, its actions, its dead-ends — and compare that across models and harnesses.

## The constraint that shapes everything

PolyRange's attacker is bring-your-own. The deployed cell only ever sees HTTP; it cannot see the agent's reasoning, and it cannot even reliably see which model is attacking. So any "capture the attacker's thinking" feature **cannot** live on the target side, and a transcript scraper would be harness-specific by definition.

The design answer is to make the *schema* the contract, not any one harness:

1. **Schema** (`polyrange-attack-trace.schema.json`) — a versioned, transport-agnostic JSON Schema describing one agent's run against one cell. This is the only thing PolyRange and harness authors have to agree on.
2. **Ingest affordance** (opt-in) — PolyRange offers an optional channel to receive a trace: a `/__pr/trace` endpoint, or an extra field on `/__pr/submit`, or simply a file dropped in `runs/<id>/traces/`. A harness that emits nothing loses nothing; existing behaviour is unchanged.
3. **Per-harness adapters** — each harness ships a thin translator from its own logs to the schema. Two reference adapters are included and tested (see Validation).
4. **Analysis pass** — a builder/judge LLM reads all traces for a cell and produces a comparative thinking-and-outcome report.

This keeps the core strict and harness-neutral while every harness plugs in optionally.

## Schema, in brief

A trace has five required parts: `schema_version`, `cell`, `agent`, `steps`, `outcome`. Full field semantics are in the schema file; the load-bearing decisions:

- **`cell.cell_id`** is the stable join key. Every agent that attacks the same deployed target emits the same `cell_id` (recommended: the per-deploy canary), so the analysis pass can line up "how did A, B, and C each approach *this* cell".
- **`agent.model_requested` vs `agent.model_served`** are separate, and `model_served` is nullable. They can differ silently — an offensive prompt can be rerouted to a different model than requested — so the schema refuses to conflate them. `model_served` is null when the harness can't verify it, and per-turn `served_model` is allowed on each step for mid-run changes.
- **`steps[].thought` is nullable by design.** Some harnesses expose model reasoning; some don't. The schema records what is actually available rather than pretending, and `provenance.capture_method` plus per-adapter notes tell the consumer how to weight it.
- **Strict core, explicit extension point.** Top-level `additionalProperties: false` keeps the contract tight; an `extensions` object is the one place harness-specific extras may go, so forward-compatibility never requires loosening the core.

## Versioning and compatibility

`schema_version` is semver. Consumers must reject an unknown **major** and may ignore unknown optional fields within a known major. New optional fields are minor bumps; required-field or semantic changes are major.

## Privacy and security

Traces contain attack payloads and recovered secrets (that's the point). Two guards: `provenance.redacted` flags whether an adapter scrubbed secrets/PII before emission, and observation bodies are size-bounded (`observation.truncated`) so a trace can't smuggle an unbounded response dump. Operators decide whether to send `target_url`/`canary` at all — both are optional.

## Adapter contract

An adapter is a pure function `(harnessLog, cellMeta, agentMeta) -> trace`. It must: assign 0-based `index`; pair each action with its observation; populate `served_model` from real per-turn evidence where the harness provides it; set honest `provenance` (`capture_method`, and a note when `thought` is narration rather than hidden reasoning). It must not invent reasoning the harness didn't produce.

## Analysis pass

Given all traces for a `cell_id`, an LLM produces a comparative report against a fixed template (phases: recon / hypothesis / exploit / exfiltrate / submit; per agent: distinct hypotheses tried, dead-ends and backtracks, productive-vs-wasted requests, reasoned-vs-brute-force signal; outcome: solved, requests-to-solve, served-model consistency). One caveat we hold firmly: a model grading its own trace is biased toward self-justification, so for any leaderboard use the grader should be a **separate** judge model (or a small panel); same-model analysis is an introspection extra, not ground truth.

## Forward work: live knowledge-graph view

The step stream is already a graph, not just a list. Nodes: endpoints, parameters, discovered tables/columns, hypotheses, the flag. Edges: `probed`, `reflected-into`, `leaks`, `confirmed-by`. With the **live** capture method (adapters emit steps as they happen rather than post-hoc), a TUI can build that graph in real time — each request adds or confirms a node, each successful inference draws an edge — giving a meaningful map of the attack surface as the agent discovers it, not a cosmetic animation. This is a natural extension of the same schema; it needs only the live-emit path and a stable node/edge vocabulary layered on `steps[].tags` + `action.detail`.

## Validation

Both reference adapters were run against **real** harness logs and their output validated against the schema with ajv (JSON Schema 2020-12):

- **Claude Code** (a Meridian-provisioned attacker vs a live SQLi cell): 18 steps, schema-valid, `solved: true`, and it correctly captured `model_served: claude-opus-4-8` despite `model_requested: claude-fable-5` — the requested-vs-served split working on real data.
- **norn / Codex** (a real rollout session): 163 steps, schema-valid, with `thought` populated from the model's visible narration and `provenance` honestly noting that Codex hidden reasoning is not exposed in its logs.

Two different harnesses, one schema, both valid — which is the whole point.
