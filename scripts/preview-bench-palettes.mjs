// Three high-contrast TUI-inspired palette options for the four-panel
// bench-comparison figure. Same data, three colour languages — pick one.

import fs from 'node:fs/promises'
import path from 'node:path'

const REPO_ROOT = process.cwd()
const SAMPLES_DIR = path.join(REPO_ROOT, 'samples', 'sqli-diversity')
const OUT_DIR = path.join(REPO_ROOT, 'preview')
const OUT_HTML = path.join(OUT_DIR, 'bench-palettes.html')
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
const dvwa = staticBenchRows(), cy = staticBenchRows(), xb = staticBenchRows()

let off = 0, offCount = 0, offMax = 0
for (const r of polyrangeRows) {
  if (r.row === r.col) continue
  off += r.value; offCount++; if (r.value > offMax) offMax = r.value
}
const offMean = off / offCount

// ── Three high-contrast TUI palettes ──────────────────────────────────────

const PALETTES = [
  {
    id: 'tokyo',
    name: 'A. Tokyo Night',
    notes: 'Dark navy panel, cool blue → neon magenta gradient. The most-used modern TUI theme.',
    paper:      '#16161e',
    panelBg:    '#1a1b26',
    rule:       '#3b4261',
    ink:        '#c0caf5',
    muted:      '#7682ad',
    accent:     '#bb9af7',
    cellRange:  ['#1a1b26', '#bb9af7'],
    cellStroke: '#24283b',
    mono:       '"JetBrains Mono", "Fira Code", monospace',
  },
  {
    id: 'cyber',
    name: 'B. Cyberpunk synthwave',
    notes: 'Near-black panel, magenta diagonal, cyan rule. High-contrast / chunky vibe like btop or k9s on a hi-res screen.',
    paper:      '#06010f',
    panelBg:    '#0c0418',
    rule:       '#2a1a3f',
    ink:        '#e6e6ff',
    muted:      '#7c6ba4',
    accent:     '#ff2a6d',
    cellRange:  ['#0c0418', '#ff2a6d'],
    cellStroke: '#1f0e30',
    mono:       '"JetBrains Mono", "Fira Code", monospace',
  },
  {
    id: 'phosphor',
    name: 'C. Phosphor / CRT terminal',
    notes: 'True black, phosphor green. Stark, retro, instantly readable as terminal output.',
    paper:      '#000000',
    panelBg:    '#050505',
    rule:       '#1a4a1a',
    ink:        '#7aff7a',
    muted:      '#3aaa3a',
    accent:     '#00ff41',
    cellRange:  ['#050505', '#00ff41'],
    cellStroke: '#0d1a0d',
    mono:       '"JetBrains Mono", "Fira Code", "Courier New", monospace',
  },
  {
    id: 'gruvbox',
    name: 'D. Gruvbox dark',
    notes: 'Warm dark brown, amber/gold accent. Popular Neovim theme; warmer feel than Tokyo Night.',
    paper:      '#1d2021',
    panelBg:    '#282828',
    rule:       '#504945',
    ink:        '#ebdbb2',
    muted:      '#a89984',
    accent:     '#fabd2f',
    cellRange:  ['#282828', '#fabd2f'],
    cellStroke: '#3c3836',
    mono:       '"JetBrains Mono", "Fira Code", monospace',
  },
]

// ── HTML ───────────────────────────────────────────────────────────────────

function paletteSection(p) {
  return `
<section class="row" style="
  --paper:${p.paper}; --panel:${p.panelBg}; --rule:${p.rule};
  --ink:${p.ink}; --muted:${p.muted}; --accent:${p.accent};
  --mono:${p.mono};
">
  <header class="row-header">
    <p class="figure-label">PALETTE ${p.id.toUpperCase()}</p>
    <h2>${p.name}</h2>
    <p class="row-notes">${p.notes}</p>
  </header>

  <div class="legend">
    <span>Pairwise Jaccard similarity</span>
    <span class="tnum">0</span>
    <span class="swatch" style="background: linear-gradient(to right, ${p.cellRange[0]}, ${p.cellRange[1]});"></span>
    <span class="tnum">1</span>
  </div>

  <div class="panels">
    ${['DVWA', 'Cybench', 'XBOW validation suite', 'PolyRange'].map((label, i) => `
      <div class="panel">
        <div class="heading">
          <h3>${label}</h3>
          <span class="panel-id">[${'ABCD'[i]}]</span>
        </div>
        <div class="plot" id="p-${p.id}-${i}"></div>
        <div class="metric">
          <span class="value">${i < 3 ? '1.000' : offMean.toFixed(3)}</span>
          <span class="metric-label">mean pairwise similarity${i === 3 ? ` · max ${offMax.toFixed(3)}` : ''}</span>
        </div>
      </div>
    `).join('')}
  </div>
</section>`
}

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Bench comparison — TUI palette options</title>
<style>
  body {
    font-family: "Inter", system-ui, sans-serif;
    background: #0b0b0d;
    color: #d0d0d6;
    margin: 0;
    padding: 30px 24px 60px;
  }
  .page { max-width: 1500px; margin: 0 auto; }

  .intro {
    background: #16161a;
    border: 1px solid #2a2a30;
    border-radius: 0;
    padding: 22px 26px;
    margin-bottom: 22px;
  }
  .intro h1 { margin: 0 0 8px; font-size: 17px; font-family: "JetBrains Mono", monospace; color: #fff; }
  .intro p  { margin: 0; color: #888; font-size: 13px; line-height: 1.55; max-width: 800px; font-family: "JetBrains Mono", monospace; }

  section.row {
    background: var(--paper);
    border: 1px solid var(--rule);
    border-radius: 0;
    padding: 32px 36px 28px;
    margin-bottom: 20px;
    font-family: var(--mono);
    color: var(--ink);
  }

  .row-header { margin-bottom: 18px; }
  .figure-label {
    font-family: var(--mono);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: var(--accent);
    margin: 0 0 6px;
    font-weight: 500;
  }
  h2 {
    font-family: var(--mono);
    font-size: 20px;
    font-weight: 700;
    margin: 0 0 6px;
    color: var(--ink);
    letter-spacing: -0.005em;
  }
  .row-notes {
    font-size: 12px;
    color: var(--muted);
    margin: 0;
    line-height: 1.55;
    font-family: var(--mono);
  }

  .legend {
    display: flex; align-items: center; gap: 14px;
    margin: 18px 0 18px;
    font-size: 11px;
    color: var(--muted);
    font-family: var(--mono);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .legend .swatch {
    display: inline-block; width: 110px; height: 9px;
    border: 1px solid var(--rule);
  }
  .legend .tnum { color: var(--ink); font-feature-settings: 'tnum'; }

  .panels {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px;
  }
  .panel {
    background: var(--panel);
    border: 1px solid var(--rule);
    border-radius: 0;
    padding: 14px 14px 12px;
    text-align: center;
  }
  .panel .heading {
    display: flex; justify-content: space-between; align-items: baseline;
    margin-bottom: 12px;
    border-bottom: 1px solid var(--rule);
    padding-bottom: 8px;
  }
  .panel h3 {
    font-family: var(--mono);
    font-weight: 600;
    font-size: 12.5px;
    margin: 0;
    color: var(--ink);
    letter-spacing: 0.02em;
  }
  .panel .panel-id {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--muted);
    letter-spacing: 0.05em;
  }
  .panel .plot { display: flex; justify-content: center; margin: 4px 0 10px; }
  .panel .metric {
    border-top: 1px solid var(--rule);
    padding-top: 8px;
    font-family: var(--mono);
    font-size: 10px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .panel .metric .value {
    font-family: var(--mono);
    font-weight: 700;
    font-size: 22px;
    color: var(--accent);
    display: block;
    margin-bottom: 2px;
    font-feature-settings: 'tnum';
  }
  .panel .metric-label {
    color: var(--muted);
    font-size: 10px;
  }
</style>
</head>
<body>

<div class="page">

  <div class="intro">
    <h1>Bench comparison — four TUI palette directions</h1>
    <p>Same data and layout. Tell me which one.</p>
  </div>

  ${PALETTES.map(paletteSection).join('\n')}

</div>

<script type="module">
import * as Plot from "https://cdn.jsdelivr.net/npm/@observablehq/plot@0.6.16/+esm";

const ids = ${JSON.stringify(ids)};
const polyrangeRows = ${JSON.stringify(polyrangeRows)};
const dvwa = ${JSON.stringify(dvwa)};
const cy   = ${JSON.stringify(cy)};
const xb   = ${JSON.stringify(xb)};
const datasets = [dvwa, cy, xb, polyrangeRows];

const PALETTES = ${JSON.stringify(PALETTES.map(({ id, cellRange, cellStroke }) => ({ id, cellRange, cellStroke })))};

for (const p of PALETTES) {
  for (let i = 0; i < 4; i++) {
    document.querySelector('#p-' + p.id + '-' + i).append(Plot.plot({
      width: 240, height: 240, marginLeft: 0, marginTop: 0, marginRight: 0, marginBottom: 0, padding: 0,
      x: { domain: ids, axis: null }, y: { domain: ids, axis: null },
      color: { type: 'linear', domain: [0, 1], range: p.cellRange },
      marks: [
        Plot.cell(datasets[i], { x: 'col', y: 'row', fill: 'value',
          stroke: p.cellStroke, strokeWidth: 0.2 }),
      ],
      style: { background: 'transparent' },
    }));
  }
}
</script>

</body>
</html>`

await fs.mkdir(OUT_DIR, { recursive: true })
await fs.writeFile(OUT_HTML, html)

console.log()
console.log('  Written: ' + path.relative(REPO_ROOT, OUT_HTML))
console.log('  open ' + path.relative(REPO_ROOT, OUT_HTML))
