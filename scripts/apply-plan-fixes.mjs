// Applies the plan.html audit fixes from the 2026-05-30 session.
//
// Each fix is an exact string replace with a unique anchor — so the script
// is idempotent: re-running it after the source has already been updated
// will be a no-op for already-applied fixes, and will surface a clear
// warning for any anchor that no longer matches (which means the source
// drifted in a way the script didn't expect).
//
// Edits preserve the full-catalogue × tier-ladder ambition for the
// publishable-N run; the OWASP-8 smoke is positioned as proof-of-pipeline,
// not as a scope reduction.

import fs from 'node:fs/promises'
import path from 'node:path'

const REPO_ROOT = process.cwd()
const PLAN_PATH = path.join(REPO_ROOT, 'plan.html')
const today = new Date().toISOString().slice(0, 10)

let plan = await fs.readFile(PLAN_PATH, 'utf-8')
let applied = 0, skipped = 0, missing = 0

function apply(label, from, to) {
  if (plan.includes(to)) {
    console.log(`  · ${label}  (already applied)`)
    skipped++
    return
  }
  if (!plan.includes(from)) {
    console.log(`  ! ${label}  (anchor not found — manual check needed)`)
    missing++
    return
  }
  plan = plan.replace(from, to)
  console.log(`  + ${label}`)
  applied++
}

console.log('Applying plan.html audit fixes')
console.log('━'.repeat(72))

// 1. Header status + last-updated
apply(
  'Header status + last-updated',
  '<strong>Status:</strong> pre-v1, conceptual design locked, implementation pending<br>\n      <strong>Author:</strong> Jamieson O\'Reilly (independent research)<br>\n      <strong>Last updated:</strong> 2026-05-24',
  `<strong>Status:</strong> v1.0 framework implemented; capability-smoke complete; publishable-N pending partnership funding<br>\n      <strong>Author:</strong> Jamieson O'Reilly (independent research)<br>\n      <strong>Last updated:</strong> ${today}`,
)

// 2. Abstract: 85 → 84
apply(
  'Abstract: class count 85 → 84',
  'v1.0 ships 85 atomics drawn from WSTG v4.2 across all 12 categories',
  'v1.0 ships 84 atomics drawn from WSTG v4.2 across all 12 categories',
)

// 3. WSTG coverage: 85 → 84
apply(
  'WSTG coverage: class count 85 → 84',
  '- **v1.0 ships 85 atomics built**',
  '- **v1.0 ships 84 atomics built**',
)

// 4. Architecture: packaged CLI ships in v1 (not v1.1)
apply(
  'Architecture: packaged CLI shipped in v1',
  'Researcher runs `node generator/deploy.mjs --class=X --target=fly` and gets a unique `https://<app-name>.fly.dev` URL out of the box with HTTPS, multi-region support, and free-tier-friendly pricing for individual evaluation runs. A packaged CLI (`polyrange deploy ...`) is a v1.1 follow-up; the framework\'s contribution does not depend on the packaging.',
  'Researcher runs `node polyrange.mjs eval` (or `node polyrange.mjs one --class=X` for a single-class debug deploy) and gets a unique `https://<app-name>.fly.dev` URL out of the box with HTTPS, multi-region support, and free-tier-friendly pricing for individual evaluation runs. The packaged CLI ships as `polyrange.mjs` at the repo root in v1.',
)

// 5. v1.0 roadmap: shipped class count
apply(
  'v1.0 roadmap: shipped class count',
  '- **As many WSTG classes as I can ship by release** — aiming for broad coverage, not a fixed cap. The framework and one or two classes are the minimum for the paper to make its claim; every additional class extends the empirical breadth. Current dev burn-in targets the first cohort (XSS, IDOR, SQLi, then command injection, SSRF, path traversal, CSRF, etc.) to prove the per-class infra-template pattern generalises, after which adding classes is a contained per-class workflow.',
  '- **84 WSTG atomics built across all 12 categories** — 6 categories complete (4.1 Information Gathering, 4.3 Identity Management, 4.5 Authorization, 4.8 Error Handling, 4.10 Business Logic, 4.12 API), the remaining 6 covering their highest-prevalence atomics. The per-class infra-template pattern generalises across stateless Node, Postgres-backed, polyglot-backend (SQLite / Postgres / MySQL), raw-socket-byte-writing, and browser-oracle-required class shapes.',
)

// 6. v1.0 roadmap: deploy entrypoint
apply(
  'v1.0 roadmap: deploy entrypoint command',
  '- **Deploy entrypoint** — `node generator/deploy.mjs --class=X --target=fly|local-docker --tier=N [--ephemeral]`. Runs the full pipeline: theme generation, scenario generation, chrome and decoys, Docker build via Fly\'s remote builder, deploy, validator (canonical exploit fires, discovery reachable, negative control), and optional teardown.',
  '- **Unified CLI entrypoint** — `node polyrange.mjs eval [--model=X --tier=0,1 --classes=all --run-id=X --yes]` for the end-to-end flow (precheck → deploy → hand-off prompt → live monitor → report → tear-down). Sub-commands: `deploy`, `monitor`, `report`, `destroy`, `one` (single-class debug deploy). Every deploy runs the canonical-exploit validator (exploit fires, discovery reachable, negative control passes) before being marked ✓.',
)

// 7. v1.0 roadmap: grade-equivalent / standalone polyrange grade
apply(
  'v1.0 roadmap: grade CLI shipped',
  '- **Grade-equivalent** — the validator is built into the deploy pipeline today; the deploy succeeds only when the canary is recovered by the canonical exploit and the negative control fails to recover it. A standalone `polyrange grade` CLI that runs an external model under test against a deployed instance is v1.1 work (see Stage 2 in north-star.md).',
  '- **End-to-end eval shipped in v1** — `polyrange eval` orchestrates the model-under-test loop: deploys, hands off a prompt naming the targets and the `/__pr/submit` confirmation protocol, polls every deployment\'s `/__pr/signature` endpoint via a live monitor, finalises a head-to-head report with Wilson 95% CIs. Standalone `polyrange report --runs=A,B` combines multiple model runs.',
)

// 8. Eval report exemplar: v0.8 → v0.9 + harness rename
apply(
  'Eval report exemplar: version + harness label',
  '║  PolyRange v0.8  —  Evaluation Report                                        ║\n║  model: claude-opus-4-7        run: 2026-05-26T14:02Z      duration: 6h11m   ║\n║  protocol: fresh-draw · N=100/cell · tiers T0,T1 · 85 atomic classes         ║\n║  17,000 ephemeral targets · agent harness: polyrange-agent v0.3 (tool-use)   ║',
  '║  PolyRange v0.9  —  Evaluation Report                                        ║\n║  model: claude-opus-4-7        run: 2026-05-26T14:02Z      duration: 6h11m   ║\n║  protocol: fresh-draw · N=100/cell · tiers T0,T1 · 84 atomic classes         ║\n║  16,800 ephemeral targets · harness: <user-supplied; bring-your-own>         ║',
)

// 9. Signature exemplar: surface the new fields the runtime now returns
apply(
  'Signature exemplar: new fields + submit endpoint',
  '  Captured live by runtime/server.mjs; read out-of-band via /__pr/signature\n  with the per-deploy controlKey. Never surfaced to the model.\n\n  {\n    "startedAt": 1748390421003,\n    "requests": 47,\n    "solved": true,\n    "solvedAt":  1748390518440,\n    "timeToSolveMs": 97437,\n    "requestsToSolve": 39,\n    "solvePayload": {\n      "method": "GET",\n      "path": "/search",\n      "query": "?q=%27+UNION+SELECT+null%2Ccredential+FROM+payment_gateway_profiles--",\n      "body": ""\n    },',
  '  Captured live by runtime/server.mjs; read out-of-band via /__pr/signature\n  with the per-deploy controlKey. The model never sees this; the agent\n  signals task completion by POSTing the recovered canary to /__pr/submit,\n  which marks the cell solved on the bench side.\n\n  {\n    "startedAt": 1748390421003,\n    "firstRequestAt": 1748390427112,\n    "requests": 47,\n    "solved": true,\n    "solvedAt": 1748390518440,\n    "solvedVia": "submit",\n    "submittedAt": 1748390518440,\n    "durationMs": 91328,\n    "requestsInSession": 39,\n    "timeToSolveMs": 91328,\n    "requestsToSolve": 39,\n    "solvePayload": {\n      "method": "GET",\n      "path": "/search",\n      "query": "?q=%27+UNION+SELECT+null%2Ccredential+FROM+payment_gateway_profiles--",\n      "body": ""\n    },',
)

// 10. Repo shape: divergence note
apply(
  'Repo shape: divergence note (CLI shipped)',
  'The polyrange CLI is exercised today via `node generator/deploy.mjs` rather than a packaged `bin/polyrange` — packaging is a v1.1 follow-up that does not block the framework\'s contribution.',
  'The polyrange CLI ships as `polyrange.mjs` at the repo root with `lib/` for the screen / monitor / report primitives. `generator/deploy.mjs` remains the underlying single-class driver wrapped by `polyrange one`.',
)

// 11. Contributions: empirical bullet — smoke complete, full plan unchanged
apply(
  'Contributions: empirical positioning',
  '3. **Empirical (planned).** I pre-register three hypotheses and present an evaluation protocol designed to quantify the *randomisation gap* between bare frontier-model performance on static versus randomised benchmarks, the *defence gap* as tier escalates from undefended to adaptive-behavioural, and the *harness gap* — the recovery of randomisation- and defence-induced performance loss when models are evaluated within an orchestration harness rather than as bare chat agents.',
  '3. **Empirical (capability-smoke complete; publishable-N pending partnership).** A single-instance capability-smoke against a frontier model has been completed on an OWASP Top 10:2025-aligned subset of the class catalogue and confirms the framework end-to-end. The full pre-registered protocol — three hypotheses across the *randomisation gap*, the *defence gap* as tier escalates from undefended through adaptive-behavioural, and the *harness gap* between bare-chat and orchestrated-agent evaluation — covers the full 84-class catalogue at publishable N per cell and remains the publishable target. The smoke is positioned as proof-of-pipeline, not as scope reduction.',
)

// 12. Thesis: add early-observations paragraph that preserves full plan
apply(
  'Thesis: early-observations paragraph',
  'The harness-gap finding is the most practically consequential: it informs where the field should be investing engineering effort. Framed as a demonstrated empirical result rather than an a priori claim.',
  `The harness-gap finding is the most practically consequential: it informs where the field should be investing engineering effort. Framed as a demonstrated empirical result rather than an a priori claim.

**Early observations (pre-research).** A capability-smoke against a frontier model across an OWASP Top 10:2025-aligned subset of the catalogue has been completed in this release window. The observations are consistent with the pre-registered hypotheses qualitatively. Statistical interpretation is reserved for the publishable-N run; the smoke confirms the framework end-to-end (deploy → hand-off → live monitor → report) but does not narrow the publishable scope, which remains all 84 classes evaluated at every implemented defence tier and extending through the tier ladder (T2 → T4) in subsequent releases.`,
)

// 13. What gets us → publishable v1: reframe smoke item
apply(
  'What gets us: reframe smoke as completed proof-of-pipeline',
  'In flight:\n5. Capability-smoke run: N=1 head-to-head between two frontier models (Opus-class + GPT-class) against the full T0 + T1 class set, scoped for blog-post publication. Produces relative-capability orientation, not publishable-N confidence intervals.\n\nRemaining:\n6. Publishable-N empirical run (requires institutional backing per the Limitations subsection).\n7. Paper finalisation, arXiv submission, public announcement.',
  `Done (continued):
5. Capability-smoke completed: a frontier-model run against an OWASP Top 10:2025-aligned 8-class subset (12 cells, T0 + T1 where T1 is implemented) confirms the framework end-to-end. Proof-of-pipeline, not a published capability claim.

Remaining:
6. Publishable-N empirical run across all 84 classes × T0 + T1 at N≥30 per cell, extending through T2 → T4 as the tier ladder ships in v1.1 and v2. Requires institutional backing per the Limitations subsection.
7. Paper finalisation, arXiv submission, public announcement.`,
)

// 14. "Done:" item 4 — same CLI reference fix
apply(
  'What gets us → Done: CLI reference',
  '4. Deploy + grade CLI minimum: `node generator/deploy.mjs --class=X --target=fly|local-docker --tier=N [--ephemeral]`. Validator runs end-to-end on every deploy (canonical exploit fires, discovery reachable, negative control passes) before the deploy is marked ✓.',
  '4. Unified `polyrange.mjs` CLI shipped with subcommands `eval`, `deploy`, `monitor`, `report`, `destroy`, `one` (single-class debug). Validator runs end-to-end on every deploy (canonical exploit fires, discovery reachable, negative control passes) before the deploy is marked ✓. Self-healing: retries on flaky deploys, auto-destroys failed Fly apps so a flaky run does not leak cost.',
)

await fs.writeFile(PLAN_PATH, plan)

console.log('━'.repeat(72))
console.log(`  ${applied} applied  ·  ${skipped} already in place  ·  ${missing} anchors missing`)
console.log()
if (missing > 0) console.log('  (re-check the missing anchors against the current source manually.)')
else console.log('  open plan.html')
