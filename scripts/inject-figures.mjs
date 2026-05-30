// Generates the contact-sheet figure and the bench-comparison figure as
// self-contained, script-free HTML/SVG blocks, then injects them into
// plan.html.
//
// Figure CSS lives in plan.html's main <style> block (injected once via
// idempotent markers) so the rules definitely apply when marked.parse
// renders the markdown via innerHTML.
//
// Figures break out of the 760px reading column to a wider band so the
// four-panel grid has room to render at usable cell sizes.
//
// Idempotent: re-running replaces both the CSS block and the figure
// blocks rather than duplicating them.

import fs from 'node:fs/promises'
import path from 'node:path'

const REPO_ROOT = process.cwd()
const SAMPLES_DIR = path.join(REPO_ROOT, 'samples', 'sqli-diversity')
const PLAN_PATH = path.join(REPO_ROOT, 'plan.html')

// ── Read the sample run + compute Jaccard ──────────────────────────────────

const index = JSON.parse(await fs.readFile(path.join(SAMPLES_DIR, 'index.json'), 'utf-8'))
const N = 50
const samples = index.samples.slice(0, N)

async function deployFeatures(dir) {
  const f = new Set()
  const sc = await readJson(path.join(dir, 'scenario.json')).catch(() => ({}))
  const th = await readJson(path.join(dir, 'theme.json')).catch(() => ({}))
  const ch = await fs.readFile(path.join(dir, 'chrome.html'), 'utf-8').catch(() => '')
  if (sc.endpoint?.path) f.add('path:' + sc.endpoint.path)
  for (const s of Object.values(sc.slots || {})) {
    if (s?.name) f.add('param:' + s.name)
    if (s?.location) f.add('loc:' + s.location)
  }
  for (const l of [...(th.navLinks || []), ...(th.secondaryLinks || [])]) {
    if (typeof l === 'string') f.add('nav:' + l)
    else if (l?.href) f.add('nav:' + l.href)
  }
  if (sc.itemsTable)     f.add('table:' + sc.itemsTable)
  if (sc.sensitiveTable) f.add('table:' + sc.sensitiveTable)
  for (const t of sc.decoyTables || []) if (t?.name) f.add('table:' + t.name)
  const txt = ch.replace(/<script[\s\S]*?<\/script>/gi, '')
                .replace(/<style[\s\S]*?<\/style>/gi, '')
                .replace(/<[^>]+>/g, ' ')
                .toLowerCase().replace(/\s+/g, ' ').trim()
  const toks = txt.split(/\W+/).filter(Boolean)
  for (let i = 0; i + 8 <= toks.length; i++) f.add('chrome8g:' + toks.slice(i, i + 8).join(' '))
  for (const tok of String(th.siteName || '').toLowerCase().split(/\s+/).filter(Boolean)) {
    f.add('site:' + tok)
  }
  return f
}
async function readJson(p) { return JSON.parse(await fs.readFile(p, 'utf-8')) }

const featureSets = []
for (const s of samples) featureSets.push(await deployFeatures(path.join(SAMPLES_DIR, s.id)))

function jaccard(a, b) {
  let inter = 0
  for (const x of a) if (b.has(x)) inter++
  const u = a.size + b.size - inter
  return u === 0 ? 0 : inter / u
}

const polyM = Array.from({ length: N }, () => new Array(N).fill(0))
for (let i = 0; i < N; i++) for (let j = 0; j < N; j++) polyM[i][j] = jaccard(featureSets[i], featureSets[j])

let off = 0, offCount = 0, offMax = 0
for (let i = 0; i < N; i++) for (let j = 0; j < N; j++) {
  if (i === j) continue
  off += polyM[i][j]; offCount++
  if (polyM[i][j] > offMax) offMax = polyM[i][j]
}
const offMean = off / offCount
const avgFeatureSetSize = featureSets.reduce((a, b) => a + b.size, 0) / N

console.log(`Real PolyRange data:`)
console.log(`  N samples:          ${N}`)
console.log(`  Mean features:      ${avgFeatureSetSize.toFixed(0)}`)
console.log(`  Off-diagonal max:   ${(offMax * 100).toFixed(2)}%`)
console.log(`  Off-diagonal mean:  ${(offMean * 100).toFixed(2)}%`)

// ── SVG render ─────────────────────────────────────────────────────────────

function rampHex(t) {
  t = Math.max(0, Math.min(1, t))
  // 0 → white; 1 → #9580FF (light SNES purple)
  const r = Math.round(255 + t * (149 - 255))
  const g = Math.round(255 + t * (128 - 255))
  const b = Math.round(255 + t * (255 - 255))
  return `rgb(${r},${g},${b})`
}

function renderPanelSVG(matrix, opts = {}) {
  const cell = opts.cell || 5.6
  const n = matrix.length
  const w = n * cell
  let svg = `<svg viewBox="0 0 ${w} ${w}" width="${w}" height="${w}" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" style="display:block">`
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      const fill = rampHex(matrix[r][c])
      svg += `<rect x="${(c * cell).toFixed(2)}" y="${(r * cell).toFixed(2)}" width="${cell.toFixed(2)}" height="${cell.toFixed(2)}" fill="${fill}" stroke="#f0eff4" stroke-width="0.18"/>`
    }
  }
  svg += '</svg>'
  return svg
}

const onesM = Array.from({ length: N }, () => new Array(N).fill(1))

// ── Figure CSS (one block, lives in plan.html's main <style>) ──────────────

const figureCSS = `
  /* === POLYRANGE_FIGURE_STYLES === */

  /* Figures stay within the 760px reading column.
     The TOC nav is fixed on the right at ≥1100px viewport — breaking out
     wider runs into it. The narrower panels are still legible because the
     visual claim is contrast (4 solid vs 1 mostly-empty), not detail. */
  .pr-figure {
    margin: 56px 0;
    padding: 0;
    width: 100%;
    max-width: 100%;
  }

  .pr-figure .pr-eyebrow {
    font-family: var(--font-mono);
    font-size: 12px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--text-soft);
    margin: 0 0 10px;
  }
  .pr-figure .pr-title {
    font-family: var(--font-sans);
    font-weight: 600;
    font-size: 22px;
    line-height: 1.25;
    letter-spacing: -0.01em;
    color: var(--text);
    margin: 0 0 8px;
  }
  .pr-figure .pr-subtitle {
    font-family: var(--font-sans);
    font-size: 15px;
    color: var(--text-muted);
    margin: 0 0 22px;
    line-height: 1.55;
    max-width: 880px;
  }

  /* Bench-comparison */
  .pr-figure-bench .pr-legend {
    display: flex; align-items: center; gap: 12px;
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-soft);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin: 0 0 18px;
  }
  .pr-figure-bench .pr-legend .pr-swatch {
    display: inline-block;
    width: 110px; height: 8px;
    background: linear-gradient(to right, #ffffff, #9580FF);
    border: 1px solid var(--border);
    border-radius: 1px;
  }
  .pr-figure-bench .pr-legend .pr-tnum {
    color: var(--text);
    font-feature-settings: 'tnum';
    text-transform: none;
  }
  .pr-figure-bench .pr-panels {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 14px;
  }
  @media (max-width: 720px) {
    .pr-figure-bench .pr-panels { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }
  @media (max-width: 480px) {
    .pr-figure-bench .pr-panels { grid-template-columns: 1fr; }
  }
  .pr-figure-bench .pr-panel {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 16px 14px 12px;
    text-align: center;
    min-width: 0;
    display: flex;
    flex-direction: column;
  }
  .pr-figure-bench .pr-panel-head {
    display: flex; justify-content: space-between; align-items: baseline;
    margin-bottom: 4px;
    flex: 0 0 auto;
  }
  .pr-figure-bench .pr-panel-head h3 {
    font-family: var(--font-sans);
    font-weight: 600;
    font-size: 14px;
    margin: 0;
    color: var(--text);
    letter-spacing: -0.005em;
  }
  .pr-figure-bench .pr-panel-id {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-soft);
    letter-spacing: 0.04em;
  }
  /* Locked vertical area for description so the SVG below starts at the
     same y in every panel regardless of how many lines the copy wraps to. */
  .pr-figure-bench .pr-panel-desc {
    font-family: var(--font-sans);
    font-size: 12px;
    color: var(--text-muted);
    margin: 4px 0 14px;
    height: 96px;
    overflow: hidden;
    line-height: 1.5;
    flex: 0 0 96px;
  }
  .pr-figure-bench .pr-plot {
    display: flex; justify-content: center;
    margin: 8px 0 14px;
    max-width: 100%;
    overflow: hidden;
    flex: 0 0 auto;
  }
  .pr-figure-bench .pr-plot svg {
    width: 100%;
    height: auto;
    max-width: 280px;
  }
  /* Metric anchored after the SVG (no margin-top: auto) so the border-top
     hits the same y across all panels regardless of metric-label wrap. */
  .pr-figure-bench .pr-metric {
    border-top: 1px solid var(--border);
    padding-top: 12px;
    font-family: var(--font-mono);
    font-size: 10.5px;
    color: var(--text-soft);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    height: 56px;             /* fixed area for value + label, accommodates
                                 1- or 2-line labels without baseline drift */
    box-sizing: content-box;
    display: flex;
    flex-direction: column;
  }
  .pr-figure-bench .pr-metric .pr-value {
    font-family: var(--font-sans);
    font-weight: 600;
    font-size: 22px;
    color: var(--text);
    display: block;
    margin-bottom: 4px;
    font-feature-settings: 'tnum';
    text-transform: none;
    letter-spacing: -0.01em;
    line-height: 1;
  }
  .pr-figure-bench .pr-notes {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 22px 26px;
    margin-top: 22px;
    font-family: var(--font-sans);
    font-size: 14px;
    color: var(--text-muted);
    line-height: 1.65;
  }
  .pr-figure-bench .pr-notes h4 {
    font-family: var(--font-mono);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-soft);
    margin: 0 0 10px;
    font-weight: 500;
  }
  .pr-figure-bench .pr-notes p { margin: 0 0 12px; }
  .pr-figure-bench .pr-notes p:last-child { margin-bottom: 0; }
  .pr-figure-bench .pr-notes em { color: var(--text); font-style: normal; font-weight: 500; }
  .pr-figure-bench .pr-notes strong { color: var(--text); font-weight: 600; font-feature-settings: 'tnum'; }
  .pr-figure-bench .pr-notes code {
    background: var(--code-bg);
    padding: 1px 5px;
    border-radius: 3px;
    font-family: var(--font-mono);
    font-size: 12.5px;
    color: var(--text);
  }
  .pr-figure-bench .pr-notes sub { font-size: 0.75em; }

  /* Contact sheet */
  .pr-figure-sheet .pr-sheet-frame {
    background: #f5f5f4;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px;
  }
  .pr-figure-sheet .pr-sheet {
    display: grid;
    grid-template-columns: repeat(10, minmax(0, 1fr));
    gap: 4px;
  }
  @media (max-width: 720px) {
    .pr-figure-sheet .pr-sheet { grid-template-columns: repeat(5, minmax(0, 1fr)); }
  }
  .pr-figure-sheet .pr-sheet a {
    display: block;
    background: #fff;
    border-radius: 2px;
    overflow: hidden;
    line-height: 0;
    min-width: 0;
  }
  .pr-figure-sheet .pr-sheet img {
    display: block;
    width: 100%;
    height: auto;
    aspect-ratio: 1280/800;
    object-fit: cover;
    object-position: top;
  }
  .pr-figure-sheet .pr-caption {
    margin-top: 12px;
    font-family: var(--font-sans);
    font-size: 13px;
    color: var(--text-muted);
    line-height: 1.55;
  }

  /* === END POLYRANGE_FIGURE_STYLES === */
`

// ── Figure HTML (no inline <style>, references plan.html's main CSS) ──────

const benchFigureHtml = `
<!-- POLYRANGE_FIGURE:bench-comparison start -->
<figure class="pr-figure pr-figure-bench">
  <p class="pr-eyebrow">Figure 1 · Per-instance feature overlap</p>
  <p class="pr-title">Pairwise Jaccard similarity across N = ${N} instances of the same vulnerability class.</p>
  <p class="pr-subtitle">
    Each panel is a ${N} × ${N} matrix whose (i, j) entry is the Jaccard similarity between the attack-surface feature sets of instances i and j of the same class. Cells closer to 1 indicate that an attack memorised against one instance applies to the other; cells closer to 0 indicate no such transfer is possible.
  </p>
  <div class="pr-legend">
    <span>Pairwise Jaccard similarity</span>
    <span class="pr-tnum">0</span>
    <span class="pr-swatch"></span>
    <span class="pr-tnum">1</span>
  </div>
  <div class="pr-panels">
    <div class="pr-panel">
      <div class="pr-panel-head"><h3>DVWA</h3><span class="pr-panel-id">A</span></div>
      <p class="pr-panel-desc">Same install on every host. Paths, parameters, and schema are constant by design.</p>
      <div class="pr-plot">${renderPanelSVG(onesM)}</div>
      <div class="pr-metric"><span class="pr-value">1.000</span>mean pairwise similarity</div>
    </div>
    <div class="pr-panel">
      <div class="pr-panel-head"><h3>Cybench</h3><span class="pr-panel-id">B</span></div>
      <p class="pr-panel-desc">Same Docker image per task. Flag and supporting files do not vary across attempts.</p>
      <div class="pr-plot">${renderPanelSVG(onesM)}</div>
      <div class="pr-metric"><span class="pr-value">1.000</span>mean pairwise similarity</div>
    </div>
    <div class="pr-panel">
      <div class="pr-panel-head"><h3>XBOW validation</h3><span class="pr-panel-id">C</span></div>
      <p class="pr-panel-desc">Static internal benchmark suite. Targets do not vary between evaluation runs.</p>
      <div class="pr-plot">${renderPanelSVG(onesM)}</div>
      <div class="pr-metric"><span class="pr-value">1.000</span>mean pairwise similarity</div>
    </div>
    <div class="pr-panel">
      <div class="pr-panel-head"><h3>PolyRange</h3><span class="pr-panel-id">D</span></div>
      <p class="pr-panel-desc">Independently LLM-generated per instance. Paths, parameters, schemas, and chrome all differ.</p>
      <div class="pr-plot">${renderPanelSVG(polyM)}</div>
      <div class="pr-metric"><span class="pr-value">${offMean.toFixed(3)}</span>mean (max ${offMax.toFixed(3)})</div>
    </div>
  </div>
  <div class="pr-notes">
    <h4>Notes</h4>
    <p><em>Panels A–C are derived, not measured.</em> DVWA, Cybench (per-task), and XBOW's validation suite all fix the attack surface across attempts by published design — every instance is the same install, Docker image, or static target. Per-instance feature overlap is therefore identically 1 across every pair, by construction. The matrices are drawn from this structural property, not from independent measurement. Fixed surfaces are necessary for the reproducibility those benchmarks target; the comparison is not pejorative.</p>
    <p><em>Panel D is measured.</em> The data come from ${N} independent PolyRange deploys of <code>wstg-sqli-4.7.5.4</code> generated on ${new Date(index.generatedAt).toISOString().slice(0, 10)} via <code>scripts/sample-class.mjs</code>. The generation pipeline uses <code>claude-opus-4-7</code> for the theme, scenario, and chrome stages (three LLM calls per deploy, ${N * 3} calls in total). For each deploy the feature set comprises the vulnerable endpoint path, parameter name and location, every navigation link in the LLM-generated chrome, every data table name, 8-gram tokens drawn from the chrome HTML, and the tokens of the site name. Across ${(N * (N - 1)).toLocaleString()} pairwise comparisons of distinct instances, the maximum overlap observed is <strong>${(offMax * 100).toFixed(2)}%</strong>; the mean is <strong>${(offMean * 100).toFixed(2)}%</strong>; mean feature-set size per instance is <strong>${avgFeatureSetSize.toFixed(0)}</strong>.</p>
    <p><em>Note on the generation model.</em> The model used here (<code>claude-opus-4-7</code>) is the model that <strong>generates</strong> the diverse target surfaces. It is independent of and distinct from any model later evaluated <strong>against</strong> those targets. PolyRange's contamination-resistance property follows from the generation step alone; a different generation model would produce different deploys, but the metric on this figure would land in the same regime so long as the generator can produce reasonably varied themes, paths, and schemas.</p>
    <p><em>Reproducibility.</em> The PolyRange panel can be re-generated end-to-end from a clean clone via <code>node scripts/sample-class.mjs --class=wstg-sqli-4.7.5.4 --count=50</code> followed by <code>node scripts/render-samples.mjs</code>. Different runs produce slightly different numbers (every deploy is a fresh LLM draw) but the order of magnitude is reproducible: mean pairwise overlap consistently lands below 1%.</p>
    <p><em>Methods.</em> Jaccard similarity is computed as &nbsp;|F<sub>i</sub> ∩ F<sub>j</sub>| / |F<sub>i</sub> ∪ F<sub>j</sub>| over feature sets F<sub>i</sub>, F<sub>j</sub>. Theme, font, palette, industry, and copy-tone features are excluded by design; they vary across deploys but do not constitute attack surface. Including them would lower the reported similarity numbers and would be dishonest about what the metric measures.</p>
  </div>
</figure>
<!-- POLYRANGE_FIGURE:bench-comparison end -->
`

function escapeAttr(s) {
  return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

const tiles = samples.map(s => `<a href="samples/sqli-diversity/${s.id}/home.png" target="_blank" rel="noreferrer"><img loading="lazy" src="samples/sqli-diversity/${s.id}/home.png" alt="${escapeAttr(s.siteName || s.id)}"></a>`).join('')

const contactSheetHtml = `
<!-- POLYRANGE_FIGURE:contact-sheet start -->
<figure class="pr-figure pr-figure-sheet">
  <p class="pr-eyebrow">Figure 2 · Per-instance surface diversity</p>
  <p class="pr-title">${N} independent PolyRange deploys of the same vulnerability class.</p>
  <p class="pr-subtitle">
    Each tile is the home page of a different LLM-generated deployment of <code>wstg-sqli-4.7.5.4</code>. Themes, navigation, copy, paths, and underlying database schemas are independently generated per deploy. The agent attacking these targets has never seen any of them before.
  </p>
  <div class="pr-sheet-frame"><div class="pr-sheet">${tiles}</div></div>
  <p class="pr-caption">
    All ${N} home pages were rendered at 1280 × 800 via headless Chromium from the LLM-generated chrome HTML. Click any tile to view it full size. No two deploys share more than ${(offMax * 100).toFixed(1)}% of their attack-surface features; see Figure 1.
  </p>
</figure>
<!-- POLYRANGE_FIGURE:contact-sheet end -->
`

// ── Inject into plan.html ──────────────────────────────────────────────────

let plan = await fs.readFile(PLAN_PATH, 'utf-8')

function replaceBlock(haystack, startMarker, endMarker, newBlock) {
  const startIdx = haystack.indexOf(startMarker)
  if (startIdx === -1) return null
  const endIdx = haystack.indexOf(endMarker, startIdx)
  if (endIdx === -1) return null
  return haystack.slice(0, startIdx) + newBlock + haystack.slice(endIdx + endMarker.length)
}

function injectAfter(haystack, anchor, block) {
  const idx = haystack.indexOf(anchor)
  if (idx === -1) throw new Error('Anchor not found: ' + anchor)
  const afterIdx = idx + anchor.length
  return haystack.slice(0, afterIdx) + '\n\n' + block + '\n' + haystack.slice(afterIdx)
}

// 1. Figure CSS — inject before </style> of plan.html's main style block.
//    Idempotent via /* === POLYRANGE_FIGURE_STYLES === */ markers.
const cssStart = '/* === POLYRANGE_FIGURE_STYLES === */'
const cssEnd   = '/* === END POLYRANGE_FIGURE_STYLES === */'

if (plan.includes(cssStart) && plan.includes(cssEnd)) {
  const startIdx = plan.indexOf(cssStart)
  const endIdx = plan.indexOf(cssEnd, startIdx) + cssEnd.length
  plan = plan.slice(0, startIdx) + figureCSS.trim() + plan.slice(endIdx)
} else {
  // Insert before the closing </style> of the main <style> block (first one).
  const closeStyleIdx = plan.indexOf('</style>')
  if (closeStyleIdx === -1) throw new Error('No </style> found in plan.html')
  plan = plan.slice(0, closeStyleIdx) + '\n' + figureCSS.trim() + '\n  ' + plan.slice(closeStyleIdx)
}

// 2. Figure blocks — replace if markers present, otherwise inject after anchors.
const thesisAnchor = 'The harness-gap finding is the most practically consequential: it informs where the field should be investing engineering effort. Framed as a demonstrated empirical result rather than an a priori claim.'
const benchAnchor = 'HIDBench ([arXiv:2605.21773](https://arxiv.org/html/2605.21773)), [Top-8 LLM cyber benchmarks (Infosecurity Europe)](https://www.infosecurityeurope.com/en-gb/blog/future-thinking/top-8-llm-benchmarks-for-cybersecurity-practices.html).'

const sheetReplaced = replaceBlock(plan, '<!-- POLYRANGE_FIGURE:contact-sheet start -->', '<!-- POLYRANGE_FIGURE:contact-sheet end -->', contactSheetHtml.trim())
plan = sheetReplaced || injectAfter(plan, thesisAnchor, contactSheetHtml.trim())

const benchReplaced = replaceBlock(plan, '<!-- POLYRANGE_FIGURE:bench-comparison start -->', '<!-- POLYRANGE_FIGURE:bench-comparison end -->', benchFigureHtml.trim())
plan = benchReplaced || injectAfter(plan, benchAnchor, benchFigureHtml.trim())

await fs.writeFile(PLAN_PATH, plan)

console.log()
console.log('  CSS:    injected into plan.html <style> block (idempotent)')
console.log('  Figure 1 (bench comparison): after "Where PolyRange slots in"')
console.log('  Figure 2 (contact sheet):    after Thesis')
console.log()
console.log('  open plan.html')
