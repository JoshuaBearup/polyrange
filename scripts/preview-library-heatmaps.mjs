// Generates a preview HTML that renders the same two heatmaps using
// Observable Plot and Vega-Lite, side-by-side, so we can compare the
// "scientific paper" aesthetic of each library against the hand-rolled
// SVGs and pick a direction.
//
// All data is simulated (50 fake deploys); libraries are loaded from CDN
// so the preview is self-contained.

import fs from 'node:fs/promises'
import path from 'node:path'
import crypto from 'node:crypto'

const REPO_ROOT = process.cwd()
const OUTPUT_DIR = path.join(REPO_ROOT, 'preview')
const OUTPUT_HTML = path.join(OUTPUT_DIR, 'library-heatmap-preview.html')

// ── Synthesise the same 50 fake deploys as the earlier preview ─────────────

const INDUSTRIES = ['manufacturing','bakery','dental','records','parcel','law','wms','patisserie','tailor','auditing','analytics','instruments','lab','archive','fintech']
const NAME_PREFIXES = ['Bramble','Hartwell','Vector','Quartz','Cobblestone','Saltreed','Copperleaf','Iron','Bench','Atlas','Harrow','Asher','Ridge','Lattice','Birch','Cinder','Slate','Tundra','Wren','Cordoba','Pinegate','Drystone','Loomwerks','Foxglove','Sandgrove','Northgate','Kettleworks','Auberon','Calder','Vellum','Mirepoix','Halcyon','Petrichor','Tarragon','Wexford','Linden','Maple','Anvil','Lockwood','Marlow','Glenmoor','Brackenfen','Kirkmoor','Stonebridge','Yarrow','Heatherwood','Norcross','Highgate','Thornbury','Westbrook']
const NAME_SUFFIXES = ['Systems','Industries','Works','Bakehouse','Records','Couriers','Law','Warehouse','Patisserie','Tailors','Audit','Analytics','Instruments','Laboratories','Archives','Pay']
const FONTS = ['Asap','Inter','Georgia','Playfair Display','JetBrains Mono','Crimson Text','Manrope','IBM Plex Sans','Source Serif Pro','EB Garamond','Roboto Slab','Spectral']
const ENDPOINTS = ['/search','/portal/parts/lookup','/inventory','/products/lookup','/catalogue/find','/shop/search','/find','/library/search','/ledger/query','/orders/search','/parts/search','/items/lookup','/registry/find','/archive/browse','/bookings/lookup','/clients/search','/transactions/find','/instruments/catalog','/specimens/lookup','/sessions/find','/menu/search','/loaves/find','/sheets/lookup','/portal/inventory/find','/admin/search','/audit/lookup','/holdings/browse','/dashboards/query']
const SLOTS = ['q','query','search','part','sku','id','item','term','lookup','find','ref','reference','code','name','tag','catalog','title','keyword','partno','partnum','asset','specimen','session','book','order','holding']
const ITEM_TABLES = ['catalogue_parts','products','items','inventory','stock','parts_catalog','sku_catalogue','line_items','catalog','goods','assets','units','wares','sheets','loaves','specimens','sessions','tracks','records','vintages','instruments','assays','clients','cases']
const SENS_TABLES = ['credentials','accounts','staff_accounts','api_clients','admin_keys','service_accounts','secrets','keystore','master_keys','session_tokens','operator_credentials','privileged_users','staff','vault','keychain','admin_users','svc_users','machine_accounts']

function mulberry32(seed) {
  let a = seed >>> 0
  return () => {
    a |= 0; a = a + 0x6D2B79F5 | 0
    let t = a
    t = Math.imul(t ^ t >>> 15, t | 1)
    t ^= t + Math.imul(t ^ t >>> 7, t | 61)
    return ((t ^ t >>> 14) >>> 0) / 4294967296
  }
}
const rng = mulberry32(0xC0FFEE)
const pick = (arr) => arr[Math.floor(rng() * arr.length)]
const hex = (n) => Array.from(crypto.randomBytes(n), b => b.toString(16).padStart(2, '0')).join('')

const prefixes = [...NAME_PREFIXES]
const deploys = Array.from({ length: 50 }, (_, i) => {
  const prefix = prefixes.splice(Math.floor(rng() * prefixes.length), 1)[0] || pick(NAME_PREFIXES)
  return {
    id: String(i + 1).padStart(3, '0'),
    siteName:        `${prefix} ${pick(NAME_SUFFIXES)}`,
    industry:        pick(INDUSTRIES),
    font:            pick(FONTS),
    endpoint:        pick(ENDPOINTS),
    slot:            pick(SLOTS),
    itemsTable:      pick(ITEM_TABLES),
    sensitiveTable:  pick(SENS_TABLES),
    canary:          'pr_' + hex(12),
  }
})

// ── Long-form data for the libraries ───────────────────────────────────────

function deployFeatureSet(d) {
  return new Set([
    'site:' + d.siteName, 'ind:' + d.industry, 'font:' + d.font,
    'end:' + d.endpoint, 'slot:' + d.slot,
    'it:' + d.itemsTable, 'st:' + d.sensitiveTable,
  ])
}

function jaccard(a, b) {
  let inter = 0
  for (const x of a) if (b.has(x)) inter++
  const u = a.size + b.size - inter
  return u === 0 ? 0 : inter / u
}

const features = deploys.map(deployFeatureSet)
const simMatrix = []
for (let i = 0; i < deploys.length; i++) {
  for (let j = 0; j < deploys.length; j++) {
    simMatrix.push({ row: deploys[i].id, col: deploys[j].id, value: jaccard(features[i], features[j]) })
  }
}

function deployTokens(d) {
  const segs = d.endpoint.split('/').filter(Boolean)
  return new Set([
    ...segs.map(s => 'p:' + s),
    'slot:' + d.slot, 'it:' + d.itemsTable, 'st:' + d.sensitiveTable,
    'font:' + d.font, 'ind:' + d.industry,
    ...d.siteName.toLowerCase().split(/\s+/).map(w => 'name:' + w),
  ])
}

const tokenSets = deploys.map(deployTokens)
const tokenCount = new Map()
for (const ts of tokenSets) for (const t of ts) tokenCount.set(t, (tokenCount.get(t) || 0) + 1)
const tokens = [...tokenCount.keys()].sort((a, b) => tokenCount.get(a) - tokenCount.get(b) || a.localeCompare(b))

const tokenMatrix = []
for (let i = 0; i < deploys.length; i++) {
  for (let k = 0; k < tokens.length; k++) {
    if (tokenSets[i].has(tokens[k])) {
      tokenMatrix.push({ deploy: deploys[i].id, token: tokens[k], freq: tokenCount.get(tokens[k]) })
    }
  }
}

// ── Render HTML ────────────────────────────────────────────────────────────

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PolyRange diversity — library heatmaps</title>
<style>
  body { font-family: 'Inter', -apple-system, system-ui, sans-serif; background: #fafafa; color: #1a1a1a; margin: 0; padding: 40px; }
  header.page { max-width: 1400px; margin: 0 auto 24px; }
  h1 { margin: 0 0 8px; font-size: 28px; }
  .sub { color: #555; max-width: 760px; line-height: 1.55; }
  .banner { background: #fef3c7; border: 1px solid #f59e0b; padding: 8px 12px; border-radius: 6px; margin-bottom: 24px; font-size: 13px; color: #92400e; max-width: 1400px; margin-left: auto; margin-right: auto; }
  section { max-width: 1400px; margin: 0 auto 56px; }
  h2 { font-size: 20px; margin: 0 0 6px; }
  h3 { font-size: 14px; margin: 0 0 8px; color: #555; text-transform: uppercase; letter-spacing: 0.04em; }
  .lead { color: #555; margin: 0 0 16px; max-width: 800px; line-height: 1.55; font-size: 14px; }
  .compare { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .card { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 20px 24px; }
  .card h3 { margin-bottom: 12px; }
  .lib-note { color: #777; font-size: 12px; margin-top: 12px; font-style: italic; }
  .compare-wide { display: grid; grid-template-columns: 1fr; gap: 16px; }
</style>
<script src="https://cdn.jsdelivr.net/npm/vega@5.30.0/build/vega.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vega-lite@5.21.0/build/vega-lite.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vega-embed@6.26.0/build/vega-embed.min.js"></script>
</head>
<body>

<div class="banner">
  <strong>SIMULATED PREVIEW.</strong> 50 fake deploys. Comparing Observable Plot
  vs Vega-Lite for the two heatmap candidates from the previous round.
</div>

<header class="page">
  <h1>Heatmaps via library — sample renderings</h1>
  <p class="sub">
    Same data, two libraries, two heatmap types. Pick the combination that
    lands the contamination-resistance story best.
  </p>
</header>

<section>
  <h2>Self-similarity matrix  (50 × 50, Jaccard)</h2>
  <p class="lead">
    Cell (i, j) = Jaccard similarity between deploy i's feature set and
    deploy j's. Diagonal is 1.0; everything else is 0. Bright off-diagonal
    cells would mark a contamination leak.
  </p>
  <div class="compare">
    <div class="card">
      <h3>Observable Plot</h3>
      <div id="plot-sim"></div>
      <div class="lib-note">scheme: viridis · cell mark · axes labelled and ticked at 5-deploy intervals</div>
    </div>
    <div class="card">
      <h3>Vega-Lite</h3>
      <div id="vega-sim"></div>
      <div class="lib-note">scheme: viridis · rect mark · auto-generated legend with colorbar</div>
    </div>
  </div>
</section>

<section>
  <h2>Token-presence sparse matrix  (50 × ${tokens.length} tokens)</h2>
  <p class="lead">
    Rows = deploys; columns = every unique token used by any deploy
    (path segments, parameter names, tables, fonts, industries).
    Sorted rare→common. A column with one warm cell means that token
    belongs to one deploy.
  </p>
  <div class="compare-wide">
    <div class="card">
      <h3>Observable Plot</h3>
      <div id="plot-tokens" style="overflow-x:auto"></div>
      <div class="lib-note">scheme: inferno · cell mark · log-coloured by token frequency</div>
    </div>
    <div class="card">
      <h3>Vega-Lite</h3>
      <div id="vega-tokens" style="overflow-x:auto"></div>
      <div class="lib-note">scheme: inferno · rect mark · log-scaled colour</div>
    </div>
  </div>
</section>

<script type="module">
import * as Plot from "https://cdn.jsdelivr.net/npm/@observablehq/plot@0.6.16/+esm";

const deploys = ${JSON.stringify(deploys.map(d => d.id))};
const simMatrix = ${JSON.stringify(simMatrix)};
const tokens = ${JSON.stringify(tokens)};
const tokenMatrix = ${JSON.stringify(tokenMatrix)};

// ── Observable Plot: self-similarity ──────────────────────────────────────

document.querySelector('#plot-sim').append(Plot.plot({
  width: 640,
  height: 640,
  marginLeft: 60,
  marginTop: 60,
  padding: 0,
  x: { domain: deploys, axis: 'top', label: 'Deploy', tickFormat: d => d.endsWith('1') || d.endsWith('6') ? d : '' },
  y: { domain: deploys, label: 'Deploy', tickFormat: d => d.endsWith('1') || d.endsWith('6') ? d : '' },
  color: { scheme: 'viridis', label: 'Jaccard similarity', legend: true, domain: [0, 1] },
  marks: [
    Plot.cell(simMatrix, { x: 'col', y: 'row', fill: 'value',
      title: d => \`\${d.row} vs \${d.col}: \${(d.value * 100).toFixed(0)}%\` }),
  ],
  style: { fontFamily: 'Inter, sans-serif', fontSize: 11, background: 'transparent' },
}));

// ── Observable Plot: token-presence ───────────────────────────────────────

document.querySelector('#plot-tokens').append(Plot.plot({
  width: Math.max(900, tokens.length * 4),
  height: 460,
  marginLeft: 60,
  marginBottom: 40,
  padding: 0,
  x: { domain: tokens, label: 'Unique tokens (sorted rare → common)', tickFormat: () => '' },
  y: { domain: deploys, label: 'Deploy', tickFormat: d => d.endsWith('1') || d.endsWith('6') ? d : '' },
  color: { scheme: 'inferno', label: 'Token frequency (log)', legend: true, type: 'log', domain: [1, 50] },
  marks: [
    Plot.cell(tokenMatrix, { x: 'token', y: 'deploy', fill: 'freq',
      title: d => \`\${d.token} → used by \${d.freq} deploy(s)\` }),
  ],
  style: { fontFamily: 'Inter, sans-serif', fontSize: 11, background: 'transparent' },
}));

// ── Vega-Lite: self-similarity ────────────────────────────────────────────

vegaEmbed('#vega-sim', {
  data: { values: simMatrix },
  width: 560, height: 560,
  mark: { type: 'rect' },
  encoding: {
    x: { field: 'col', type: 'ordinal', title: 'Deploy',
         axis: { orient: 'top', labelExpr: "indexof(['001','006','011','016','021','026','031','036','041','046','050'], datum.value) >= 0 ? datum.value : ''" } },
    y: { field: 'row', type: 'ordinal', title: 'Deploy',
         axis: { labelExpr: "indexof(['001','006','011','016','021','026','031','036','041','046','050'], datum.value) >= 0 ? datum.value : ''" } },
    color: { field: 'value', type: 'quantitative', scale: { scheme: 'viridis', domain: [0, 1] },
             legend: { title: 'Jaccard similarity', orient: 'right' } },
    tooltip: [{ field: 'row' }, { field: 'col' }, { field: 'value', format: '.2f' }],
  },
  config: { view: { stroke: null }, font: 'Inter, sans-serif', axis: { grid: false } },
});

// ── Vega-Lite: token-presence ─────────────────────────────────────────────

vegaEmbed('#vega-tokens', {
  data: { values: tokenMatrix },
  width: Math.max(900, tokens.length * 4), height: 420,
  mark: { type: 'rect' },
  encoding: {
    x: { field: 'token', type: 'ordinal', sort: null, title: 'Unique tokens (sorted rare → common)',
         axis: { labels: false, ticks: false } },
    y: { field: 'deploy', type: 'ordinal', title: 'Deploy',
         axis: { labelExpr: "indexof(['001','006','011','016','021','026','031','036','041','046','050'], datum.value) >= 0 ? datum.value : ''" } },
    color: { field: 'freq', type: 'quantitative', scale: { scheme: 'inferno', type: 'log', domain: [1, 50] },
             legend: { title: 'Token frequency (log)' } },
    tooltip: [{ field: 'token' }, { field: 'deploy' }, { field: 'freq' }],
  },
  config: { view: { stroke: null }, font: 'Inter, sans-serif', axis: { grid: false } },
});
</script>

</body>
</html>`

await fs.mkdir(OUTPUT_DIR, { recursive: true })
await fs.writeFile(OUTPUT_HTML, html)

console.log()
console.log('  Preview written to:')
console.log('    ' + path.relative(REPO_ROOT, OUTPUT_HTML))
console.log()
console.log('  Open:')
console.log('    open ' + path.relative(REPO_ROOT, OUTPUT_HTML))
console.log()
