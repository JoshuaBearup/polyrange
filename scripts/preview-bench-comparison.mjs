// Four-panel benchmark comparison. DVWA / Cybench / XBOW panels are
// synthesised at 1.0 similarity (every attempt at a fixed-surface benchmark
// presents the same attack surface). PolyRange panel pulls the real
// similarity matrix from samples/sqli-diversity/.
//
// Visual style: sequential blue, white background, restrained typography
// — meant to fit alongside a paper-style document, not a marketing page.

import fs from 'node:fs/promises'
import path from 'node:path'

const REPO_ROOT = process.cwd()
const SAMPLES_DIR = path.join(REPO_ROOT, 'samples', 'sqli-diversity')
const OUT_DIR = path.join(REPO_ROOT, 'preview')
const OUT_HTML = path.join(OUT_DIR, 'bench-comparison.html')
const N = 50

const index = JSON.parse(await fs.readFile(path.join(SAMPLES_DIR, 'index.json'), 'utf-8'))
const samples = index.samples.slice(0, N)

async function deployFeatures(dir) {
  const features = new Set()
  const scenario = await readJson(path.join(dir, 'scenario.json')).catch(() => ({}))
  const theme    = await readJson(path.join(dir, 'theme.json')).catch(() => ({}))
  const chrome   = await fs.readFile(path.join(dir, 'chrome.html'), 'utf-8').catch(() => '')
  if (scenario.endpoint?.path) features.add('path:' + scenario.endpoint.path)
  for (const slot of Object.values(scenario.slots || {})) {
    if (slot?.name) features.add('param:' + slot.name)
    if (slot?.location) features.add('loc:' + slot.location)
  }
  for (const l of [...(theme.navLinks || []), ...(theme.secondaryLinks || [])]) {
    if (typeof l === 'string') features.add('nav:' + l)
    else if (l?.href) features.add('nav:' + l.href)
  }
  if (scenario.itemsTable)     features.add('table:' + scenario.itemsTable)
  if (scenario.sensitiveTable) features.add('table:' + scenario.sensitiveTable)
  for (const t of scenario.decoyTables || []) if (t?.name) features.add('table:' + t.name)
  const chromeText = chrome.replace(/<script[\s\S]*?<\/script>/gi, '')
                            .replace(/<style[\s\S]*?<\/style>/gi, '')
                            .replace(/<[^>]+>/g, ' ')
                            .toLowerCase().replace(/\s+/g, ' ').trim()
  const toks = chromeText.split(/\W+/).filter(Boolean)
  for (let i = 0; i + 8 <= toks.length; i++) features.add('chrome8g:' + toks.slice(i, i + 8).join(' '))
  for (const tok of String(theme.siteName || '').toLowerCase().split(/\s+/).filter(Boolean)) {
    features.add('site:' + tok)
  }
  return features
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

const polyrangeRows = []
for (let i = 0; i < samples.length; i++) {
  for (let j = 0; j < samples.length; j++) {
    polyrangeRows.push({ row: samples[i].id, col: samples[j].id, value: jaccard(featureSets[i], featureSets[j]) })
  }
}

const ids = samples.map(s => s.id)
function staticBenchRows() {
  const rows = []
  for (const r of ids) for (const c of ids) rows.push({ row: r, col: c, value: 1.0 })
  return rows
}
const dvwaRows    = staticBenchRows()
const cybenchRows = staticBenchRows()
const xbowRows    = staticBenchRows()

let off = 0, offCount = 0, offMax = 0
for (const r of polyrangeRows) {
  if (r.row === r.col) continue
  off += r.value; offCount++; if (r.value > offMax) offMax = r.value
}
const offMean = off / offCount
const pairs = samples.length * (samples.length - 1)
const avgFeatureSetSize = (featureSets.reduce((a, b) => a + b.size, 0) / featureSets.length)

console.log(`PolyRange off-diagonal max:  ${(offMax * 100).toFixed(2)}%`)
console.log(`PolyRange off-diagonal mean: ${(offMean * 100).toFixed(3)}%`)
console.log(`Pairs evaluated:             ${pairs.toLocaleString()}`)
console.log(`Mean features per instance:  ${avgFeatureSetSize.toFixed(0)}`)

// ── HTML ───────────────────────────────────────────────────────────────────

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Per-instance feature overlap — benchmark comparison</title>
<style>
  :root {
    --serif: "Source Serif Pro", "Charter", Georgia, serif;
    --sans: "Geist", ui-sans-serif, system-ui, -apple-system, sans-serif;
    --mono: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  :root {
    /* Matches plan.html — Stone palette + periwinkle accent */
    --paper: #fafaf9;            /* stone-50 */
    --panel: #ffffff;
    --rule: #e7e5e4;             /* stone-200 */
    --rule-strong: #d6d3d1;      /* stone-300 */
    --ink: #1c1917;              /* stone-900 */
    --muted: #57534e;            /* stone-600 */
    --soft: #78716c;             /* stone-500 */
    --accent: #B5B6E4;           /* periwinkle */
    --accent-deep: #7A7BC4;      /* deeper periwinkle for cell-fill endpoint */
    --code-bg: #f5f5f4;          /* stone-100 */
  }
  body {
    font-family: var(--sans);
    background: var(--paper);
    color: var(--ink);
    margin: 0;
    padding: 56px 48px 80px;
    line-height: 1.7;
    -webkit-font-smoothing: antialiased;
    font-feature-settings: "ss01", "cv11";
  }
  .page { max-width: 1480px; margin: 0 auto; }

  .figure-label {
    font-family: var(--mono);
    font-size: 12px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--soft);
    margin: 0 0 12px;
  }
  h1.title {
    font-family: var(--sans);
    font-weight: 600;
    font-size: 24px;
    line-height: 1.2;
    margin: 0 0 10px;
    color: var(--ink);
    letter-spacing: -0.015em;
  }
  p.subtitle {
    font-family: var(--sans);
    font-size: 15px;
    color: var(--muted);
    margin: 0 0 32px;
    max-width: 880px;
    line-height: 1.6;
  }

  .panels { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 28px; }
  .panel {
    background: var(--panel);
    border: 1px solid var(--rule);
    border-radius: 6px;
    padding: 18px 16px 14px;
    text-align: center;
  }
  .panel .heading {
    display: flex; align-items: baseline; justify-content: space-between;
    margin-bottom: 4px;
  }
  .panel .heading h3 {
    font-family: var(--sans);
    font-weight: 600;
    font-size: 14px;
    margin: 0;
    letter-spacing: -0.005em;
    color: var(--ink);
  }
  .panel .heading .panel-id {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--soft);
    letter-spacing: 0.04em;
  }
  .panel .desc {
    font-size: 12px;
    color: var(--muted);
    margin: 4px 0 14px;
    min-height: 36px;
    line-height: 1.5;
  }
  .panel .plot { display: flex; justify-content: center; margin: 8px 0 14px; }
  .panel .metric {
    border-top: 1px solid var(--rule);
    padding-top: 12px;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--soft);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .panel .metric .value {
    font-family: var(--sans);
    font-weight: 600;
    font-size: 22px;
    color: var(--ink);
    display: block;
    margin-bottom: 4px;
    font-feature-settings: 'tnum';
    text-transform: none;
    letter-spacing: -0.01em;
  }

  .legend {
    display: flex; align-items: center; gap: 14px;
    margin-top: 8px; margin-bottom: 24px;
    font-size: 12px; color: var(--soft);
    font-family: var(--mono);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .legend .swatch {
    display: inline-block;
    width: 110px; height: 8px;
    background: linear-gradient(to right, #ffffff, #7A7BC4);
    border: 1px solid var(--rule);
    border-radius: 1px;
  }
  .legend .tnum { color: var(--ink); font-feature-settings: 'tnum'; text-transform: none; }

  .notes {
    background: var(--panel);
    border: 1px solid var(--rule);
    border-radius: 6px;
    padding: 22px 26px;
    font-size: 14px;
    color: var(--muted);
    line-height: 1.65;
    max-width: 980px;
  }
  .notes h4 {
    font-family: var(--mono);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--soft);
    margin: 0 0 10px;
    font-weight: 500;
  }
  .notes p { margin: 0 0 12px; }
  .notes p:last-child { margin-bottom: 0; }
  .notes em { color: var(--ink); font-style: normal; font-weight: 500; }
  .notes strong { color: var(--ink); font-weight: 600; font-feature-settings: 'tnum'; }
  .notes code {
    background: var(--code-bg);
    padding: 1px 5px;
    border-radius: 3px;
    font-family: var(--mono);
    font-size: 12.5px;
    color: var(--ink);
  }
  .notes sub { font-size: 0.75em; }
</style>
</head>
<body>

<div class="page">
  <p class="figure-label">Figure 1 · Per-instance feature overlap</p>
  <h1 class="title">Pairwise Jaccard similarity across N = ${samples.length} instances of the same vulnerability class.</h1>
  <p class="subtitle">
    Each panel is a ${samples.length} × ${samples.length} matrix whose (i, j) entry is the Jaccard similarity between the attack-surface feature sets of instances i and j of the same class. Cells closer to 1 indicate that an attack memorised against one instance applies to the other; cells closer to 0 indicate no such transfer is possible.
  </p>

  <div class="legend">
    <span>Jaccard similarity:</span>
    <span style="font-feature-settings:'tnum'">0</span>
    <span class="swatch"></span>
    <span style="font-feature-settings:'tnum'">1</span>
  </div>

  <div class="panels">

    <div class="panel">
      <div class="heading"><h3>DVWA</h3><span class="panel-id">A</span></div>
      <p class="desc">Same install on every host; vulnerability paths, parameters, and database schema are constant across instances.</p>
      <div class="plot" id="p-dvwa"></div>
      <div class="metric"><span class="value">1.000</span>mean pairwise similarity</div>
    </div>

    <div class="panel">
      <div class="heading"><h3>Cybench</h3><span class="panel-id">B</span></div>
      <p class="desc">One Docker image per challenge; the flag and supporting files are constant across attempts at the same task.</p>
      <div class="plot" id="p-cybench"></div>
      <div class="metric"><span class="value">1.000</span>mean pairwise similarity</div>
    </div>

    <div class="panel">
      <div class="heading"><h3>XBOW validation suite</h3><span class="panel-id">C</span></div>
      <p class="desc">Static internal benchmark targets; per the published methodology, suite contents do not vary between runs.</p>
      <div class="plot" id="p-xbow"></div>
      <div class="metric"><span class="value">1.000</span>mean pairwise similarity</div>
    </div>

    <div class="panel">
      <div class="heading"><h3>PolyRange</h3><span class="panel-id">D</span></div>
      <p class="desc">Each instance is independently LLM-generated. Paths, parameter names, schemas, and chrome differ across all instances.</p>
      <div class="plot" id="p-poly"></div>
      <div class="metric"><span class="value">${offMean.toFixed(3)}</span>mean pairwise similarity (max ${offMax.toFixed(3)})</div>
    </div>

  </div>

  <div class="notes">
    <h4>Notes</h4>
    <p>
      <em>Panels A–C are derived, not measured.</em> DVWA, Cybench
      (per-task), and XBOW's validation suite all fix the attack surface
      across attempts by published design — every instance is the same
      install, Docker image, or static target. Per-instance feature
      overlap is therefore identically 1 across every pair, by
      construction. The matrices are drawn from this structural property
      of those benchmarks, not from independent measurement. Fixed
      surfaces are necessary for the reproducibility those benchmarks
      target; the comparison is not pejorative.
    </p>
    <p>
      <em>Panel D is measured.</em> The data come from ${samples.length} independent
      PolyRange deploys of <code>wstg-sqli-4.7.5.4</code> generated
      ${index.generatedAt ? `on ${new Date(index.generatedAt).toISOString().slice(0, 10)}` : ''}
      via <code>scripts/sample-class.mjs</code>. The generation pipeline
      uses <code>claude-opus-4-7</code> for the theme, scenario, and
      chrome stages (three LLM calls per deploy, ${samples.length * 3} calls in total).
      For each deploy the feature set comprises the vulnerable endpoint
      path, parameter name and location, every navigation link in the
      LLM-generated chrome, every data table name, 8-gram tokens drawn
      from the chrome HTML, and the tokens of the site name. Across
      ${pairs.toLocaleString()} pairwise comparisons of distinct instances, the
      maximum overlap observed is <strong>${(offMax * 100).toFixed(2)}%</strong>;
      the mean is <strong>${(offMean * 100).toFixed(2)}%</strong>;
      mean feature-set size per instance is <strong>${avgFeatureSetSize.toFixed(0)}</strong>.
    </p>
    <p>
      <em>Note on the generation model.</em> The model used here
      (<code>claude-opus-4-7</code>) is the model that <strong>generates</strong>
      the diverse target surfaces. It is independent of and distinct from
      any model later evaluated <strong>against</strong> those targets.
      PolyRange's contamination-resistance property follows from the
      generation step alone; a different generation model would produce
      different deploys, but the metric on this figure would land in the
      same regime so long as the model can produce reasonably varied
      themes, paths, and schemas.
    </p>
    <p>
      <em>Reproducibility.</em> The PolyRange panel can be re-generated
      end-to-end from a clean clone via
      <code>node scripts/sample-class.mjs --class=wstg-sqli-4.7.5.4 --count=50</code>
      followed by <code>node scripts/render-samples.mjs</code>. Different
      runs will produce slightly different numbers (every deploy is a
      fresh LLM draw) but the order of magnitude is reproducible: mean
      pairwise overlap consistently lands below 1%.
    </p>
    <p>
      <em>Methods.</em> Jaccard similarity is computed as
      &nbsp;|F<sub>i</sub> ∩ F<sub>j</sub>| / |F<sub>i</sub> ∪ F<sub>j</sub>|
      over feature sets F<sub>i</sub>, F<sub>j</sub>. Theme, font, palette,
      industry, and copy-tone features are excluded by design; they vary
      across deploys but do not constitute attack surface. Including
      them would lower the reported similarity numbers and would be
      dishonest about what the metric measures.
    </p>
  </div>
</div>

<script type="module">
import * as Plot from "https://cdn.jsdelivr.net/npm/@observablehq/plot@0.6.16/+esm";

const ids = ${JSON.stringify(ids)};
const polyrangeRows = ${JSON.stringify(polyrangeRows)};
const dvwaRows    = ${JSON.stringify(dvwaRows)};
const cybenchRows = ${JSON.stringify(cybenchRows)};
const xbowRows    = ${JSON.stringify(xbowRows)};

function renderPanel(targetId, rows) {
  document.querySelector(targetId).append(Plot.plot({
    width: 260, height: 260,
    marginLeft: 0, marginTop: 0, marginRight: 0, marginBottom: 0, padding: 0,
    x: { domain: ids, axis: null }, y: { domain: ids, axis: null },
    color: {
      // Periwinkle ramp matching the blog's accent palette
      // 0 → white panel · 1 → deepened periwinkle (#7A7BC4)
      type: 'linear',
      domain: [0, 1],
      range: ['#ffffff', '#7A7BC4'],
    },
    marks: [
      Plot.cell(rows, { x: 'col', y: 'row', fill: 'value',
        stroke: '#f0eff4', strokeWidth: 0.25 }),
    ],
    style: { background: 'transparent' },
  }));
}

renderPanel('#p-dvwa',    dvwaRows);
renderPanel('#p-cybench', cybenchRows);
renderPanel('#p-xbow',    xbowRows);
renderPanel('#p-poly',    polyrangeRows);
</script>

</body>
</html>`

await fs.mkdir(OUT_DIR, { recursive: true })
await fs.writeFile(OUT_HTML, html)

console.log()
console.log('  Written: ' + path.relative(REPO_ROOT, OUT_HTML))
console.log('  open ' + path.relative(REPO_ROOT, OUT_HTML))
