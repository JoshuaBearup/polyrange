// Adds two things to plan.html, idempotently:
//
// 1. A new "Jaggedness and asymmetric capability training" section that
//    argues: training feedback loops shaped by current benchmarks reinforce
//    capabilities on undefended/static targets; real adversaries train
//    against the production threat distribution. The result is a widening
//    asymmetry that current methodology cannot measure.
//
// 2. A Mermaid flowchart of the end-to-end eval pipeline, placed at the
//    top of "Architecture decisions". Loads mermaid.js from CDN and
//    initialises it after marked.parse has rendered the markdown.

import fs from 'node:fs/promises'
import path from 'node:path'

const REPO_ROOT = process.cwd()
const PLAN_PATH = path.join(REPO_ROOT, 'plan.html')

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

console.log('Adding jaggedness section + mermaid eval-flow diagram')
console.log('━'.repeat(72))

// ── 1. Mermaid CDN + init in the post-render script block ──────────────────

const mermaidCdn = '<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>'

apply(
  'Mermaid: CDN script before marked.js',
  '<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>',
  `${mermaidCdn}\n<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>`,
)

apply(
  'Mermaid: init + render after marked.parse',
  '  document.getElementById(\'content\').innerHTML = html;\n\n  // Build TOC from h2 headings',
  `  document.getElementById('content').innerHTML = html;

  // Initialise mermaid with the plan.html palette + Geist typography.
  // marked produces <pre><code class="language-mermaid">…</code></pre>;
  // we swap those into <div class="mermaid"> so mermaid.run can find them.
  if (window.mermaid) {
    mermaid.initialize({
      startOnLoad: false,
      theme: 'base',
      themeVariables: {
        primaryColor:        '#fafaf9',
        primaryTextColor:    '#1c1917',
        primaryBorderColor:  '#9580FF',
        lineColor:           '#78716c',
        secondaryColor:      '#ede9fe',
        tertiaryColor:       '#ffffff',
        background:          'transparent',
        fontFamily:          'Geist, ui-sans-serif, system-ui, sans-serif',
        fontSize:            '14px',
      },
      flowchart: { curve: 'basis', useMaxWidth: true, htmlLabels: false, nodeSpacing: 30, rankSpacing: 36, padding: 8 },
    });
    document.querySelectorAll('pre code.language-mermaid').forEach((code) => {
      const wrap = document.createElement('div');
      wrap.className = 'mermaid';
      wrap.textContent = code.textContent;
      code.parentElement.replaceWith(wrap);
    });
    mermaid.run();
  }

  // Build TOC from h2 headings`,
)

// ── 2. Mermaid figure wrapper styles in the main <style> block ─────────────

const mermaidCSS = `
  /* === POLYRANGE_MERMAID_STYLES === */
  .pr-flow {
    margin: 32px 0 48px;
    padding: 24px 20px 18px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  .pr-flow .pr-flow-eyebrow {
    font-family: var(--font-mono);
    font-size: 12px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--text-soft);
    margin: 0 0 6px;
  }
  .pr-flow .pr-flow-title {
    font-family: var(--font-sans);
    font-weight: 600;
    font-size: 18px;
    margin: 0 0 18px;
    color: var(--text);
    letter-spacing: -0.005em;
  }
  .pr-flow .mermaid {
    display: flex;
    justify-content: center;
    font-family: var(--font-sans);
  }
  .pr-flow .mermaid svg {
    max-width: 100% !important;
    height: auto !important;
  }
  /* === END POLYRANGE_MERMAID_STYLES === */
`

if (!plan.includes('/* === POLYRANGE_MERMAID_STYLES === */')) {
  const anchor = '/* === END POLYRANGE_FIGURE_STYLES === */'
  if (plan.includes(anchor)) {
    plan = plan.replace(anchor, anchor + '\n' + mermaidCSS.trim())
    console.log('  + Mermaid CSS appended to figure styles block')
    applied++
  } else {
    console.log('  ! Mermaid CSS anchor not found')
    missing++
  }
} else {
  console.log('  · Mermaid CSS  (already applied)')
  skipped++
}

// ── 3. Insert the Mermaid eval-flow diagram inside Architecture decisions ──

const evalFlowBlock = `
<div class="pr-flow">
  <p class="pr-flow-eyebrow">Figure 3 · End-to-end evaluation flow</p>
  <p class="pr-flow-title">From researcher invocation through agent attack to confidence-interval-bearing report.</p>

\`\`\`mermaid
flowchart TD
    A[polyrange eval] --> B[LLM generates<br/>theme + scenario + chrome]
    B --> C[Docker build<br/>+ Fly deploy]
    C --> D{Validator<br/>passes?}
    D -- no, retry --> B
    D -- yes --> E[Hand-off prompt<br/>to agent harness]
    E --> F[Agent attacks<br/>over HTTP]
    F -- POST /__pr/submit --> G[Runtime records<br/>solve + timing]
    G --> H[Monitor polls<br/>/__pr/signature]
    H --> I[Report<br/>Wilson 95% CIs]

    classDef step fill:#ffffff,stroke:#9580FF,stroke-width:1.5px,color:#1c1917
    classDef val  fill:#ede9fe,stroke:#9580FF,stroke-width:1.5px,color:#1c1917
    class A,B,C,E,F,G,H,I step
    class D val
\`\`\`

</div>
`

apply(
  'Mermaid diagram: insert into Architecture decisions',
  '## Architecture decisions (locked)\n\n### Deployment platform: Docker via Fly.io',
  '## Architecture decisions (locked)\n' + evalFlowBlock + '\n### Deployment platform: Docker via Fly.io',
)

// ── 4. Jaggedness section between "Why this matters" and "Realistic..." ──

const jaggednessSection = `## Jaggedness and asymmetric capability training

AI capability is *jagged* — models excel at some tasks and fail at structurally similar ones, often without an obvious surface explanation. The jaggedness is a documented property of contemporary frontier models, observed across reasoning, coding, and adversarial domains. In benchmark-driven fields it has a directional consequence: capability is reinforced wherever the training loop can attach a reward signal, and is *not* reinforced where no signal exists.

The asymmetry that follows is under-acknowledged in offensive AI evaluation. The cluster of capabilities current benchmarks measure — one-shot CTF puzzle-solving, source-code pattern recognition, isolated vulnerability identification against undefended surfaces — overlaps closely with the cluster of capabilities frontier models have already been *trained to optimise*. Post-training reward signals derived from benchmark performance reinforce the patterns that benchmarks score. The training loop tightens around the benchmark distribution.

Real adversaries face no such constraint. Their training feedback comes from production engagements against defended, populated, surface-randomised environments. The capabilities that get reinforced in adversarial workflows are precisely the capabilities current benchmarks do not measure and current training loops do not select for: operational stealth, multi-step exploitation under active defence, recovery from defence-induced exploit failure, reasoning about downstream defensive consequences before acting, distinguishing sensitive data from realistic noise.

The asymmetry compounds. The field is investing capability development in the direction of the benchmarks, while the threat landscape is moving in the direction of the production conditions. At every iteration of the training-and-benchmarking loop, the gap between *measured* capability and *operational* capability widens. Models trained against undefended, static, contamination-prone benchmarks will continue to score well on those benchmarks. Whether they translate to defensive value in production conditions is, separately, an empirical question — and one current methodology cannot answer.

Capability that has been jaggedly trained toward bench-shaped patterns is exactly the capability that fails to transfer under defence. A model that has not been trained to recover from a WAF-induced exploit failure does not develop the recovery skill simply by being benchmarked against undefended targets. The training signal isn't there. The jagged peak — *can solve undefended-and-labelled CTF tasks* — exists alongside a jagged trough — *cannot operate under signature WAF plus class-conditional logic*. The trough is the part that translates to operational risk; the peak is the part the field is currently optimising for.

PolyRange is the methodology that brings the trough into the measurement frame. By aligning the benchmark distribution with the production threat condition — randomised surface, real backing infrastructure, tiered defence, no class pre-disclosure — the bench numbers and the operational numbers track in the same direction. The capability the field measures becomes the capability the field can train against and trust to deploy. Conversely: a model that performs well on PolyRange is not just a model that recognises the right CTF pattern. It is a model that has demonstrated the operational behaviours defenders actually need.

This is the strategic case for moving the eval frontier. It is not that current benchmarks are *wrong* in some abstract sense; they measure what they measure, and what they measure has its uses. It is that the capabilities they measure are not the capabilities defenders care about, and the training-and-eval loop the field has built around them is reinforcing the wrong jagged peaks.

---

`

apply(
  'Jaggedness section between "Why this matters" and "Realistic environments"',
  'This is the deeper case for the methodology. PolyRange is not built to make benchmarks harder for sport. It is built so that the capability the field measures is the capability that, when present in trained models, actually translates into defensive value.\n\n---\n\n## Realistic environments: measuring impact, not detection',
  'This is the deeper case for the methodology. PolyRange is not built to make benchmarks harder for sport. It is built so that the capability the field measures is the capability that, when present in trained models, actually translates into defensive value.\n\n---\n\n' + jaggednessSection + '## Realistic environments: measuring impact, not detection',
)

await fs.writeFile(PLAN_PATH, plan)

console.log('━'.repeat(72))
console.log(`  ${applied} applied  ·  ${skipped} already in place  ·  ${missing} anchors missing`)
console.log()
if (missing === 0) console.log('  open plan.html')
