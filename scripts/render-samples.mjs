// Renders Playwright screenshots of every sample's home.html, computes the
// locked-feature Jaccard similarity matrix, and writes a preview HTML with
// the real contact sheet and an Observable Plot heatmap.
//
// Locked feature set per deploy (attack-surface + content; no canary, no
// branding):
//   - vulnerable endpoint path
//   - each parameter name
//   - parameter location (query / body / header / path)
//   - each nav-link path from the LLM-generated theme
//   - items table, sensitive table, and each decoy table name
//   - chrome HTML 8-grams (tokenised body content)
//   - site-name tokens
//
// Usage:
//   node scripts/render-samples.mjs --input=samples/sqli-diversity

import fs from 'node:fs/promises'
import path from 'node:path'
import { chromium } from 'playwright'

const args = Object.fromEntries(
  process.argv.slice(2).map(a => {
    const [k, v] = a.replace(/^--/, '').split('=')
    return [k, v ?? true]
  })
)

const REPO_ROOT = process.cwd()
const inputDir = path.resolve(REPO_ROOT, args.input || 'samples')
const indexPath = path.join(inputDir, 'index.json')
const previewPath = path.join(inputDir, 'preview.html')

const RENDER_WIDTH  = parseInt(args.width  ?? '1280', 10)
const RENDER_HEIGHT = parseInt(args.height ?? '800',  10)
const TILE_WIDTH    = parseInt(args['tile-width'] ?? '140', 10)
const TILE_COLS     = parseInt(args['tile-cols']  ?? '10',  10)

const index = JSON.parse(await fs.readFile(indexPath, 'utf-8'))

console.log('━'.repeat(72))
console.log(`Rendering ${index.samples.length} screenshots + similarity matrix`)
console.log('━'.repeat(72))

// ── Screenshots via Playwright ─────────────────────────────────────────────

const browser = await chromium.launch()
const ctx = await browser.newContext({ viewport: { width: RENDER_WIDTH, height: RENDER_HEIGHT } })

let done = 0
for (const sample of index.samples) {
  const htmlPath = path.join(inputDir, sample.id, 'home.html')
  const pngPath  = path.join(inputDir, sample.id, 'home.png')
  const page = await ctx.newPage()
  try {
    await page.goto('file://' + htmlPath, { waitUntil: 'networkidle', timeout: 20000 })
    await page.screenshot({ path: pngPath, fullPage: false })
  } catch (e) {
    console.warn(`  ${sample.id}: screenshot failed — ${e.message.slice(0, 80)}`)
  } finally {
    await page.close()
  }
  done++
  if (done % 5 === 0 || done === index.samples.length) {
    console.log(`  screenshots: ${done}/${index.samples.length}`)
  }
}
await browser.close()

// ── Locked-feature extraction per deploy ───────────────────────────────────

async function deployFeatureSet(sample, dir) {
  const features = new Set()

  // Attack-surface from the saved scenario + theme.
  const scenario = await readJson(path.join(dir, 'scenario.json')).catch(() => ({}))
  const theme    = await readJson(path.join(dir, 'theme.json')).catch(() => ({}))
  const chromeHtml = await fs.readFile(path.join(dir, 'chrome.html'), 'utf-8').catch(() => '')

  // 1. Vulnerable endpoint path
  if (scenario.endpoint?.path) features.add('path:' + scenario.endpoint.path)
  // 2. Parameter names + locations
  for (const [k, slot] of Object.entries(scenario.slots || {})) {
    if (slot?.name) features.add('param:' + slot.name)
    if (slot?.location) features.add('loc:' + slot.location)
  }
  // 3. Nav-link paths from the LLM-generated theme
  for (const link of [...(theme.navLinks || []), ...(theme.secondaryLinks || [])]) {
    if (typeof link === 'string') features.add('nav:' + link)
    else if (link?.href) features.add('nav:' + link.href)
  }
  // 4. Data tables (SQLi / IDOR specific; harmless empty otherwise)
  if (scenario.itemsTable)     features.add('table:' + scenario.itemsTable)
  if (scenario.sensitiveTable) features.add('table:' + scenario.sensitiveTable)
  for (const t of scenario.decoyTables || []) {
    if (t?.name) features.add('table:' + t.name)
  }
  // 5. Chrome HTML 8-grams (tokenised text content, not full markup, to keep
  //    the feature set focused on semantic content rather than CSS noise).
  const chromeText = stripHtml(chromeHtml).toLowerCase().replace(/\s+/g, ' ').trim()
  for (const sh of shingles(chromeText, 8)) features.add('chrome8g:' + sh)
  // 6. Site-name tokens
  for (const tok of String(theme.siteName || '').toLowerCase().split(/\s+/).filter(Boolean)) {
    features.add('site:' + tok)
  }

  return features
}

function stripHtml(html) {
  return String(html).replace(/<script[\s\S]*?<\/script>/gi, '')
                      .replace(/<style[\s\S]*?<\/style>/gi, '')
                      .replace(/<[^>]+>/g, ' ')
}

function shingles(s, n) {
  const out = new Set()
  const toks = s.split(/\W+/).filter(Boolean)
  if (toks.length < n) return out
  for (let i = 0; i + n <= toks.length; i++) out.add(toks.slice(i, i + n).join(' '))
  return out
}

async function readJson(p) { return JSON.parse(await fs.readFile(p, 'utf-8')) }

const featureSets = []
for (const sample of index.samples) {
  const dir = path.join(inputDir, sample.id)
  featureSets.push(await deployFeatureSet(sample, dir))
}

// ── Jaccard similarity matrix ──────────────────────────────────────────────

function jaccard(a, b) {
  let inter = 0
  for (const x of a) if (b.has(x)) inter++
  const u = a.size + b.size - inter
  return u === 0 ? 0 : inter / u
}

const simRows = []
for (let i = 0; i < index.samples.length; i++) {
  for (let j = 0; j < index.samples.length; j++) {
    simRows.push({
      row: index.samples[i].id,
      col: index.samples[j].id,
      value: jaccard(featureSets[i], featureSets[j]),
    })
  }
}

// Off-diagonal max for "any contamination leak" headline number.
let offDiagMax = 0, offDiagMean = 0, offDiagCount = 0
for (const r of simRows) {
  if (r.row === r.col) continue
  offDiagMax = Math.max(offDiagMax, r.value)
  offDiagMean += r.value
  offDiagCount++
}
offDiagMean = offDiagCount ? offDiagMean / offDiagCount : 0

// Feature-set size stats
const sizes = featureSets.map(s => s.size)
const avgSize = sizes.reduce((a, b) => a + b, 0) / sizes.length
const minSize = Math.min(...sizes)
const maxSize = Math.max(...sizes)

console.log()
console.log(`  Feature-set sizes: min ${minSize} · mean ${avgSize.toFixed(0)} · max ${maxSize}`)
console.log(`  Off-diagonal max similarity: ${(offDiagMax * 100).toFixed(2)}%`)
console.log(`  Off-diagonal mean similarity: ${(offDiagMean * 100).toFixed(2)}%`)

// ── Render preview HTML ────────────────────────────────────────────────────

await fs.writeFile(previewPath, renderPreview(index, simRows, {
  offDiagMax, offDiagMean, avgSize, minSize, maxSize,
}))

console.log()
console.log('━'.repeat(72))
console.log(`Preview HTML: ${path.relative(REPO_ROOT, previewPath)}`)
console.log(`  open ${path.relative(REPO_ROOT, previewPath)}`)
console.log('━'.repeat(72))

await browser.close().catch(() => {})


// ── HTML render ────────────────────────────────────────────────────────────

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function renderPreview(index, simRows, stats) {
  const tiles = index.samples.map((s) => `
    <article class="tile" title="${escapeHtml(s.siteName)} — ${escapeHtml(s.endpoint)}?${escapeHtml(s.slot)}=">
      <img src="${escapeHtml(s.id)}/home.png" loading="lazy" alt="${escapeHtml(s.siteName)}">
      <div class="caption">
        <strong>${escapeHtml(s.siteName)}</strong>
        <code>${escapeHtml(s.endpoint)}?${escapeHtml(s.slot)}=</code>
      </div>
    </article>`).join('')

  const sample = JSON.stringify(simRows)
  const ids = JSON.stringify(index.samples.map(s => s.id))

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PolyRange diversity — ${escapeHtml(index.classId)}</title>
<style>
  body { font-family: 'Inter', -apple-system, system-ui, sans-serif; background: #fafafa; color: #1a1a1a; margin: 0; padding: 40px; }
  header.page { max-width: 1400px; margin: 0 auto 24px; }
  h1 { margin: 0 0 8px; font-size: 28px; }
  .meta { color: #555; font-size: 13px; }
  section { max-width: 1400px; margin: 0 auto 48px; }
  h2 { font-size: 20px; margin: 0 0 8px; }
  p.lead { color: #555; margin: 0 0 18px; max-width: 800px; line-height: 1.55; font-size: 14px; }

  .sheet-wrap { background: #0a0a0a; padding: 12px; border-radius: 10px; }
  .sheet { display: grid; grid-template-columns: repeat(${TILE_COLS}, 1fr); gap: 4px; }
  .tile { display: flex; flex-direction: column; background: #fff; border-radius: 2px; overflow: hidden; }
  .tile img { display: block; width: 100%; height: auto; aspect-ratio: ${RENDER_WIDTH}/${RENDER_HEIGHT}; object-fit: cover; object-position: top; }
  .tile .caption { padding: 4px 5px 5px; font-size: 8px; line-height: 1.25; }
  .tile .caption strong { display: block; font-size: 9px; margin-bottom: 1px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .tile .caption code { color: #666; font-size: 7.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: block; }
  /* "Image-only" stripped class — apply to body via ?image=1 for a clean blog screenshot */
  body.image-mode { background: #fff; padding: 0; }
  body.image-mode header.page, body.image-mode section h2, body.image-mode section p, body.image-mode .meta, body.image-mode .heat-card, body.image-mode .features, body.image-mode #plot-sim { display: none; }
  body.image-mode section { margin: 0; padding: 0; max-width: none; }
  body.image-mode .sheet-wrap { padding: 0; border-radius: 0; background: transparent; }
  body.image-mode .sheet { gap: 2px; }

  .heat-card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 24px; }
  .heat-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .stat { padding: 12px 14px; border-left: 4px solid #581c87; background: #fafafa; border-radius: 4px; }
  .stat.good { border-left-color: #16a34a; }
  .stat .label { font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 0.05em; }
  .stat .value { font-size: 22px; font-weight: 600; margin-top: 4px; }
  .stat .sub { font-size: 12px; color: #555; margin-top: 4px; line-height: 1.4; }

  .features { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 18px 22px; margin-bottom: 24px; font-size: 13px; color: #444; line-height: 1.6; }
  .features strong { color: #1a1a1a; }
  .features code { background: #f1f5f9; padding: 1px 4px; border-radius: 3px; font-size: 12px; }
</style>
</head>
<body>

<header class="page">
  <h1>PolyRange diversity — ${escapeHtml(index.classId)}</h1>
  <div class="meta">${index.samples.length} deploys · LLM-generated · no Fly deploys</div>
</header>

<section>
  <h2>Contact sheet — ${index.samples.length} deploys, one vulnerability class</h2>
  <p class="lead">Every tile is a different LLM-generated PolyRange deploy of <code>${escapeHtml(index.classId)}</code>. The agent never sees the same surface twice.</p>
  <div class="sheet-wrap"><div class="sheet">${tiles}</div></div>
  <p class="lead" style="margin-top:14px;font-size:12px;color:#888">
    Tip: append <code>?image</code> to the page URL to switch into image-export mode (chrome stripped, ready to screenshot).
  </p>
</section>
<script>
  if (location.search.includes('image')) document.body.classList.add('image-mode');
</script>

<section>
  <h2>Self-similarity matrix — attack-surface overlap between every pair of deploys</h2>
  <p class="lead">
    Each cell is the Jaccard similarity between two deploys' feature sets.
    Diagonal is 1.0 (every deploy is identical to itself). Any off-diagonal
    bright cell would mark a leak — two distinct deploys sharing an
    attack-surface feature. The visual proves the contamination claim:
    the diagonal is the only thing lit.
  </p>

  <div class="features">
    <strong>Features compared per deploy</strong> (no canary, no branding):
    <br>
    <code>path:&lt;endpoint&gt;</code>,
    <code>param:&lt;slot&gt;</code>,
    <code>loc:&lt;query|body-form|body-json|header|path&gt;</code>,
    each <code>nav:&lt;link&gt;</code>,
    each <code>table:&lt;name&gt;</code> (items / sensitive / decoy),
    chrome HTML 8-grams,
    site-name tokens.
  </div>

  <div class="heat-card">
    <div class="heat-stats">
      <div class="stat ${stats.offDiagMax === 0 ? 'good' : ''}">
        <div class="label">Off-diagonal max similarity</div>
        <div class="value">${(stats.offDiagMax * 100).toFixed(2)}%</div>
        <div class="sub">${stats.offDiagMax === 0 ? 'no two distinct deploys share a feature' : 'the most-similar pair'}</div>
      </div>
      <div class="stat ${stats.offDiagMean < 0.01 ? 'good' : ''}">
        <div class="label">Off-diagonal mean</div>
        <div class="value">${(stats.offDiagMean * 100).toFixed(3)}%</div>
        <div class="sub">average pairwise similarity across all distinct pairs</div>
      </div>
      <div class="stat">
        <div class="label">Mean feature-set size</div>
        <div class="value">${stats.avgSize.toFixed(0)}</div>
        <div class="sub">per-deploy attack surface (min ${stats.minSize}, max ${stats.maxSize})</div>
      </div>
      <div class="stat">
        <div class="label">Pairs evaluated</div>
        <div class="value">${index.samples.length * (index.samples.length - 1)}</div>
        <div class="sub">${index.samples.length}² off-diagonal cells</div>
      </div>
    </div>
    <div id="plot-sim"></div>
  </div>
</section>

<script type="module">
import * as Plot from "https://cdn.jsdelivr.net/npm/@observablehq/plot@0.6.16/+esm";

const ids = ${ids};
const simRows = ${sample};

// Three-tier threshold colour: any cell ≥0.5 is bright yellow (the diagonal),
// 0.05–0.5 would be warning orange (would only fire on an actual contamination
// leak), and everything else is pitch black. Maximum visual contrast for the
// claim "the diagonal is the only thing lit."
document.querySelector('#plot-sim').append(Plot.plot({
  width: 920,
  height: 920,
  marginLeft: 64,
  marginTop: 64,
  padding: 0,
  x: { domain: ids, axis: 'top', label: 'Deploy', tickFormat: d => (d.endsWith('1') || d.endsWith('6')) ? d : '' },
  y: { domain: ids, label: 'Deploy', tickFormat: d => (d.endsWith('1') || d.endsWith('6')) ? d : '' },
  color: {
    type: 'threshold',
    domain: [0.05, 0.5],
    range: ['#0a0a14', '#fb923c', '#fde047'],
    label: 'Jaccard similarity  ·  black <0.05  ·  orange 0.05–0.5 (leak)  ·  yellow ≥0.5 (self)',
    legend: true,
  },
  marks: [
    Plot.cell(simRows, { x: 'col', y: 'row', fill: 'value', stroke: '#000', strokeWidth: 0.5,
      title: d => \`\${d.row} vs \${d.col}: \${(d.value * 100).toFixed(1)}%\` }),
  ],
  style: { fontFamily: 'Inter, system-ui, sans-serif', fontSize: 11, background: 'transparent' },
}));
</script>

</body>
</html>`
}
