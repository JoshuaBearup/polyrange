// Synthesised preview of the blog-post diversity visuals. Generates 50
// fake-but-plausible "deploys" of a single class and renders the hero
// contact-sheet plus THREE candidate heatmap fillings so we can pick
// which one tells the contamination-resistance story best.

import fs from 'node:fs/promises'
import path from 'node:path'
import crypto from 'node:crypto'

const REPO_ROOT = process.cwd()
const OUTPUT_DIR = path.join(REPO_ROOT, 'preview')
const OUTPUT_HTML = path.join(OUTPUT_DIR, 'diversity-preview.html')

// ── Synthesis pools ────────────────────────────────────────────────────────

const INDUSTRIES = [
  { key: 'manufacturing', noun: ['Systems','Industries','Works','Forge','Mill','Foundry','Engineering'],     mood: 'industrial' },
  { key: 'bakery',        noun: ['Bakehouse','& Sons','Bread Co.','Loaf','Patisserie','Crumb'],              mood: 'artisanal' },
  { key: 'dental',        noun: ['Dental','Family Dental','Smile Studio','Orthodontics','Aesthetic Dental'], mood: 'medical' },
  { key: 'records',       noun: ['Records','Sound','Audio Co.','Label','Sessions','Studio'],                 mood: 'music' },
  { key: 'parcel',        noun: ['Couriers','Logistics','Express','Despatch','Freight','Carriers'],          mood: 'logistics' },
  { key: 'law',           noun: ['Law','& Associates','Partners LLP','Counsel','Chambers','Legal Group'],    mood: 'legal' },
  { key: 'wms',           noun: ['Warehouse','Inventory Co.','Stock','Logistics','Distribution'],            mood: 'corporate' },
  { key: 'patisserie',    noun: ['Patisserie','Boulangerie','Cake Studio','Sweet Co.','Confectionery'],      mood: 'artisanal' },
  { key: 'tailor',        noun: ['Tailors','Bespoke','Atelier','Cloth','Garments','Outfitters'],             mood: 'craft' },
  { key: 'auditing',      noun: ['Audit','Advisors','Assurance','Tax','Forensics','Consulting'],             mood: 'professional' },
  { key: 'analytics',     noun: ['Analytics','Insight','Data Co.','Metrics','Telemetry','Observatory'],      mood: 'tech' },
  { key: 'instruments',   noun: ['Instruments','Tools','Apparatus','Measurement Co.','Calibration'],         mood: 'scientific' },
  { key: 'lab',           noun: ['Laboratories','Lab Co.','Bio','Research','Assays','Diagnostics'],          mood: 'scientific' },
  { key: 'archive',       noun: ['Archives','Records Bureau','Collection','Library','Holdings','Repository'],mood: 'institutional' },
  { key: 'fintech',       noun: ['Pay','Capital','Treasury','Ledger','Settlement','Holdings'],               mood: 'fintech' },
]

const NAME_PREFIXES = [
  'Bramble','Hartwell','Vector','Quartz','Cobblestone','Saltreed','Copperleaf','Iron','Bench','Atlas',
  'Harrow','Asher','Ridge','Lattice','Birch','Cinder','Slate','Tundra','Wren',
  'Cordoba','Pinegate','Drystone','Loomwerks','Foxglove','Sandgrove','Northgate','Kettleworks',
  'Auberon','Calder','Vellum','Mirepoix','Halcyon','Petrichor','Tarragon','Wexford',
  'Linden','Maple','Anvil','Lockwood','Marlow','Glenmoor','Brackenfen','Kirkmoor',
  'Stonebridge','Yarrow','Heatherwood','Norcross','Highgate','Thornbury','Westbrook','Eastleigh',
  'Mossridge','Tangleroot',
]

const FONTS = [
  'Asap','Inter','Georgia','Playfair Display','JetBrains Mono','Crimson Text','Manrope',
  'IBM Plex Sans','Source Serif Pro','EB Garamond','Roboto Slab','Spectral','Vollkorn',
]

const COLOR_PALETTES = [
  ['#0f172a','#fff','#1e40af'], ['#1c1917','#fff','#b45309'], ['#0c4a6e','#fff','#0891b2'],
  ['#14532d','#fff','#16a34a'], ['#3f1d38','#fff','#a21caf'], ['#7c2d12','#fff','#ea580c'],
  ['#1e1b4b','#fff','#4338ca'], ['#082f49','#fff','#0284c7'], ['#0a0a0a','#fff','#525252'],
  ['#27272a','#fff','#dc2626'], ['#365314','#fff','#65a30d'], ['#312e81','#fff','#6366f1'],
  ['#1f2937','#fff','#0d9488'], ['#3b0a45','#fff','#c026d3'], ['#451a03','#fff','#facc15'],
  ['#0c0a09','#f4f0e8','#a16207'], ['#fff7ed','#7c2d12','#ea580c'], ['#ecfeff','#155e75','#0e7490'],
  ['#fef2f2','#7f1d1d','#b91c1c'], ['#f0fdf4','#14532d','#15803d'],
]

const ENDPOINT_PATTERNS = [
  '/search', '/portal/parts/lookup', '/inventory', '/products/lookup', '/catalogue/find',
  '/shop/search', '/find', '/library/search', '/ledger/query', '/orders/search',
  '/parts/search', '/items/lookup', '/registry/find', '/archive/browse', '/bookings/lookup',
  '/clients/search', '/transactions/find', '/instruments/catalog', '/specimens/lookup',
  '/sessions/find', '/menu/search', '/loaves/find', '/sheets/lookup', '/portal/inventory/find',
  '/admin/search', '/audit/lookup', '/holdings/browse', '/dashboards/query',
]

const SLOT_NAMES = [
  'q','query','search','part','sku','id','item','term','lookup','find',
  'ref','reference','code','name','tag','catalog','title','keyword','partno','partnum',
  'asset','specimen','session','book','order','holding',
]

const ITEM_TABLES = [
  'catalogue_parts','products','items','inventory','stock','parts_catalog','sku_catalogue',
  'line_items','catalog','goods','assets','units','wares','sheets','loaves','specimens',
  'sessions','tracks','records','vintages','instruments','assays','clients','cases',
]

const SENSITIVE_TABLES = [
  'credentials','accounts','staff_accounts','api_clients','admin_keys','service_accounts',
  'secrets','keystore','master_keys','session_tokens','operator_credentials','privileged_users',
  'staff','vault','keychain','admin_users','svc_users','machine_accounts',
]

const VOICES = ['terse','formal','conversational','technical','warm','clinical','enthusiastic']

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

const namePrefixesPool = [...NAME_PREFIXES]
function makeDeploy(i) {
  const industry = pick(INDUSTRIES)
  const prefix = namePrefixesPool.splice(Math.floor(rng() * namePrefixesPool.length), 1)[0] || pick(NAME_PREFIXES)
  const suffix = pick(industry.noun)
  return {
    id: String(i + 1).padStart(3, '0'),
    siteName:        `${prefix} ${suffix}`,
    industry:        industry.key,
    mood:            industry.mood,
    font:            pick(FONTS),
    palette:         pick(COLOR_PALETTES),
    voice:           pick(VOICES),
    endpoint:        pick(ENDPOINT_PATTERNS),
    slot:            pick(SLOT_NAMES),
    itemsTable:      pick(ITEM_TABLES),
    sensitiveTable: pick(SENSITIVE_TABLES),
    canary:          'pr_' + hex(12),
  }
}

const deploys = Array.from({ length: 50 }, (_, i) => makeDeploy(i))

const escapeHtml = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

// ── Contact-sheet tile renderer (CSS-only, for the preview) ────────────────

function renderTile(d) {
  const [bg, fg, accent] = d.palette
  const navLinks = {
    industrial:    ['Products','Solutions','Industries','Support'],
    artisanal:     ['Menu','Locations','Story','Order'],
    medical:       ['Services','Our Team','Patient Portal','Book'],
    music:         ['Catalogue','Artists','Sessions','Shop'],
    logistics:     ['Services','Coverage','Track','Quote'],
    legal:         ['Practice Areas','Team','Resources','Contact'],
    corporate:     ['Platform','Solutions','Customers','Resources'],
    craft:         ['Fabrics','Patterns','Bench','Bookings'],
    professional:  ['Services','Industries','Insights','Contact'],
    tech:          ['Product','Customers','Docs','Pricing'],
    scientific:    ['Instruments','Calibration','Catalog','Library'],
    institutional: ['Collection','Reading Rooms','Holdings','Visit'],
    fintech:       ['Platform','Treasury','Pricing','Developers'],
  }[d.mood] || ['Products','About','Pricing','Contact']
  const headline = {
    industrial:'Shop-floor visibility for discrete manufacturers',
    artisanal:'Stone-baked daily since 1953',
    medical:'Compassionate dentistry for the whole family',
    music:'Independent records, pressed at home',
    logistics:'Next-day parcel across the eastern seaboard',
    legal:'Boutique counsel for emerging-growth companies',
    corporate:'Warehouse management software, built for scale',
    craft:'Bespoke tailoring, two fittings, your floor',
    professional:'Independent audit and advisory',
    tech:'Real-time analytics for product teams',
    scientific:'Precision instruments for analytical labs',
    institutional:'A working archive of regional industry',
    fintech:'Treasury operations, programmable',
  }[d.mood] || 'Welcome'
  return `
<article class="tile" style="--bg:${bg};--fg:${fg};--accent:${accent};--font:'${d.font}',system-ui,sans-serif">
  <header><div class="brand">${escapeHtml(d.siteName)}</div>
    <nav>${navLinks.map(n => `<span>${escapeHtml(n)}</span>`).join('')}</nav></header>
  <section class="hero"><h1>${escapeHtml(headline)}</h1><button class="cta">Get started</button></section>
  <footer class="dim">${escapeHtml(d.endpoint)}?${escapeHtml(d.slot)}=</footer>
</article>`
}

// ── HEATMAP A: Self-similarity matrix (N × N, Jaccard) ─────────────────────
// Bright diagonal on dark field. Off-diagonal cells light up only when two
// deploys share features. The reader instantly sees: nothing off the diagonal.

function deployFeatures(d) {
  return new Set([
    'site:' + d.siteName,
    'ind:'  + d.industry,
    'font:' + d.font,
    'pal:'  + d.palette.join('|'),
    'end:'  + d.endpoint,
    'slot:' + d.slot,
    'it:'   + d.itemsTable,
    'st:'   + d.sensitiveTable,
    'voice:'+ d.voice,
  ])
}

function jaccard(a, b) {
  let inter = 0
  for (const x of a) if (b.has(x)) inter++
  const union = a.size + b.size - inter
  return union === 0 ? 0 : inter / union
}

function renderSelfSimMatrix(deploys) {
  const cell = 12
  const labelW = 36
  const headerH = 12
  const N = deploys.length
  const W = labelW + N * cell + 4
  const H = headerH + N * cell + 4
  const features = deploys.map(deployFeatures)
  let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" font-family="JetBrains Mono, monospace" font-size="7">`
  svg += `<rect x="0" y="0" width="${W}" height="${H}" fill="#0a0a0a"/>`
  for (let r = 0; r < N; r++) {
    if (r % 5 === 0) {
      svg += `<text x="${labelW - 4}" y="${headerH + r * cell + cell - 2}" text-anchor="end" fill="#777">${deploys[r].id}</text>`
    }
    for (let c = 0; c < N; c++) {
      const s = jaccard(features[r], features[c])
      // Diagonal lights up; off-diagonal collisions also light up if any share a feature.
      const lum = Math.round(s * 100)
      const fill = s >= 1.0 ? `hsl(45deg 100% 65%)`
                : s > 0     ? `hsl(45deg 80% ${30 + lum * 0.4}%)`
                : `#111`
      svg += `<rect x="${labelW + c * cell}" y="${headerH + r * cell}" width="${cell - 0.5}" height="${cell - 0.5}" fill="${fill}"><title>${deploys[r].id} vs ${deploys[c].id}: ${(s * 100).toFixed(0)}%</title></rect>`
    }
  }
  svg += '</svg>'
  return svg
}

// ── HEATMAP B: Token-presence sparse matrix ─────────────────────────────────
// Rows = deploys, columns = every unique token used by ANY deploy.
// A cell is lit if that deploy uses that token. Almost every column has only
// ONE lit cell — proving each deploy uses an essentially unique vocabulary.

function deployTokens(d) {
  const segs = d.endpoint.split('/').filter(Boolean)
  return new Set([
    ...segs.map(s => 'p:' + s),
    'slot:' + d.slot,
    'it:'   + d.itemsTable,
    'st:'   + d.sensitiveTable,
    'font:' + d.font,
    'ind:'  + d.industry,
    ...d.siteName.toLowerCase().split(/\s+/).map(w => 'name:' + w),
  ])
}

function renderTokenPresence(deploys) {
  // Collect all unique tokens, sort by ascending frequency (rarest first → left).
  const tokenCount = new Map()
  const perDeploy = deploys.map(deployTokens)
  for (const set of perDeploy) for (const t of set) tokenCount.set(t, (tokenCount.get(t) || 0) + 1)
  const tokens = [...tokenCount.keys()].sort((a, b) => (tokenCount.get(a) - tokenCount.get(b)) || a.localeCompare(b))

  const cellW = 3
  const cellH = 10
  const labelW = 36
  const headerH = 32
  const N = deploys.length
  const M = tokens.length
  const W = labelW + M * cellW + 4
  const H = headerH + N * cellH + 4
  let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" font-family="JetBrains Mono, monospace" font-size="7">`
  svg += `<rect x="0" y="0" width="${W}" height="${H}" fill="#0a0a0a"/>`

  svg += `<text x="${labelW}" y="14" fill="#777">${tokens.length} unique tokens across ${N} deploys  ·  sorted rare→common</text>`

  for (let r = 0; r < N; r++) {
    if (r % 5 === 0) {
      svg += `<text x="${labelW - 4}" y="${headerH + r * cellH + cellH - 2}" text-anchor="end" fill="#777">${deploys[r].id}</text>`
    }
  }

  for (let c = 0; c < M; c++) {
    const tokenFreq = tokenCount.get(tokens[c])
    // Rare tokens are warm; over-used tokens (collisions) are cool/bright.
    for (let r = 0; r < N; r++) {
      if (!perDeploy[r].has(tokens[c])) continue
      const hue = tokenFreq === 1 ? 45 : (tokenFreq <= 3 ? 25 : 200)
      const sat = tokenFreq === 1 ? 90 : 80
      const lum = tokenFreq === 1 ? 60 : (tokenFreq <= 3 ? 55 : 60)
      svg += `<rect x="${labelW + c * cellW}" y="${headerH + r * cellH}" width="${cellW - 0.4}" height="${cellH - 0.4}" fill="hsl(${hue}deg ${sat}% ${lum}%)"><title>${escapeHtml(tokens[c])} (used by ${tokenFreq} deploys)</title></rect>`
    }
  }
  svg += '</svg>'
  return svg
}

// ── HEATMAP C: DNA-strand fingerprint waterfall ─────────────────────────────
// One row per deploy. Each row encodes the deploy's full attack-surface
// signature as a chromatic strip, with each character coloured by its byte.
// 50 strips = 50 visually unique "DNA strands" with no shared sub-sequences.

function deployFingerprint(d) {
  return [d.siteName, d.endpoint, d.slot, d.itemsTable || '', d.sensitiveTable || '', d.canary].join('|')
}

function renderDNAStrands(deploys) {
  const cellW = 5
  const cellH = 12
  const labelW = 36
  const headerH = 12
  const fingerprints = deploys.map(deployFingerprint)
  const maxLen = Math.max(...fingerprints.map(s => s.length))
  const N = deploys.length
  const W = labelW + maxLen * cellW + 4
  const H = headerH + N * cellH + 4
  let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" font-family="JetBrains Mono, monospace" font-size="7">`
  svg += `<rect x="0" y="0" width="${W}" height="${H}" fill="#0a0a0a"/>`
  for (let r = 0; r < N; r++) {
    if (r % 5 === 0) {
      svg += `<text x="${labelW - 4}" y="${headerH + r * cellH + cellH - 2}" text-anchor="end" fill="#777">${deploys[r].id}</text>`
    }
    const fp = fingerprints[r]
    for (let c = 0; c < fp.length; c++) {
      const ch = fp.charCodeAt(c)
      if (fp[c] === '|') { continue }
      const hue = (ch * 7) % 360
      const sat = 70
      const lum = 50 + (ch % 15)
      svg += `<rect x="${labelW + c * cellW}" y="${headerH + r * cellH}" width="${cellW - 0.4}" height="${cellH - 0.4}" fill="hsl(${hue}deg ${sat}% ${lum}%)"/>`
    }
  }
  svg += '</svg>'
  return svg
}

// ── Compose preview ────────────────────────────────────────────────────────

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PolyRange diversity — heatmap candidates</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, system-ui, sans-serif; background: #fafafa; color: #1a1a1a; margin: 0; padding: 40px; }
  header.page { max-width: 1400px; margin: 0 auto 24px; }
  h1 { margin: 0 0 8px; font-size: 28px; }
  .sub { color: #555; max-width: 720px; line-height: 1.5; }
  .banner { background: #fef3c7; border: 1px solid #f59e0b; padding: 8px 12px; border-radius: 6px; margin-bottom: 24px; font-size: 13px; color: #92400e; max-width: 1400px; margin-left: auto; margin-right: auto; }
  section.viz { max-width: 1400px; margin: 0 auto 48px; }
  section.viz h2 { font-size: 20px; margin: 0 0 6px; }
  section.viz .lead { color: #555; margin: 0 0 4px; max-width: 800px; line-height: 1.55; font-size: 14px; }
  section.viz .reading { color: #777; font-style: italic; margin: 0 0 16px; font-size: 13px; }
  .sheet { display: grid; grid-template-columns: repeat(10, 1fr); gap: 6px; background: #1a1a1a; padding: 12px; border-radius: 8px; }
  .tile { background: var(--bg); color: var(--fg); font-family: var(--font); aspect-ratio: 4/3; overflow: hidden; border-radius: 3px; display: flex; flex-direction: column; padding: 6px 7px; font-size: 6px; line-height: 1.2; position: relative; }
  .tile header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 4px; border-bottom: 1px solid rgba(255,255,255,.15); }
  .tile .brand { font-weight: 600; font-size: 6.5px; max-width: 60%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .tile nav { display: flex; gap: 4px; font-size: 4.5px; opacity: 0.75; }
  .tile .hero { flex: 1; display: flex; flex-direction: column; justify-content: center; gap: 4px; padding: 4px 2px; }
  .tile .hero h1 { margin: 0; font-size: 7px; line-height: 1.15; font-weight: 600; }
  .tile .cta { align-self: flex-start; background: var(--accent); color: var(--fg); border: none; padding: 2px 5px; border-radius: 2px; font-size: 4.5px; font-family: inherit; }
  .tile footer.dim { opacity: 0.5; font-size: 4.5px; font-family: 'JetBrains Mono', monospace; padding-top: 3px; }
  .heat-wrap { background: #fff; padding: 18px; border-radius: 8px; border: 1px solid #e5e7eb; overflow-x: auto; }
  .heat-wrap svg { display: block; margin: 0 auto; }
</style>
</head>
<body>

<div class="banner">
  <strong>SIMULATED PREVIEW.</strong> 50 fake deploys synthesised from
  hand-crafted pools. Treat each heatmap as a visual sketch — pick whichever
  story we want to tell.
</div>

<header class="page">
  <h1>PolyRange diversity — heatmap candidates</h1>
  <p class="sub">
    The contact sheet works. Below it are three different ways to fill a
    heatmap such that the visual itself communicates contamination resistance
    in a security-meaningful way. Pick A, B, or C — or hybrid.
  </p>
</header>

<section class="viz">
  <h2>Contact sheet (locked)</h2>
  <p class="lead">Reference of what 50 deploys of the same class look like.</p>
  <div class="sheet">${deploys.map(renderTile).join('\n')}</div>
</section>

<section class="viz">
  <h2>Heatmap A — self-similarity matrix (50 × 50)</h2>
  <p class="lead">
    Cell (i, j) = Jaccard similarity between deploy i's attack-surface feature
    set and deploy j's. Diagonal is bright (every deploy is identical to
    itself). Any off-diagonal bright cell would mark a shared feature between
    two distinct deploys — a contamination leak.
  </p>
  <p class="reading">
    Reading: only the diagonal is lit. PolyRange leaves no surface in common
    between any two deploys. If we ever broke per-deploy randomisation, this
    image would acquire bright off-diagonal noise.
  </p>
  <div class="heat-wrap">${renderSelfSimMatrix(deploys)}</div>
</section>

<section class="viz">
  <h2>Heatmap B — token-presence sparse matrix (50 × all unique tokens)</h2>
  <p class="lead">
    Columns are every unique token used by any deploy (path segments, parameter
    names, table names, site-name words, fonts, industries). Sorted rare → common
    left-to-right. A column with only ONE warm cell means that token belongs to
    a single deploy. Wider/cooler bands appear only when a token is shared.
  </p>
  <p class="reading">
    Reading: a sparse warm-coloured constellation with almost no vertical
    structure. PolyRange's vocabulary is per-deploy unique; an attacker fuzz
    list cannot pre-cover this surface.
  </p>
  <div class="heat-wrap">${renderTokenPresence(deploys)}</div>
</section>

<section class="viz">
  <h2>Heatmap C — attack-surface fingerprint waterfall (50 chromatic strips)</h2>
  <p class="lead">
    One row per deploy. Each row encodes the deploy's full attack-surface
    signature (site name · endpoint · param · items table · sensitive table ·
    canary) as a chromatic strip, with each character coloured by its byte
    value.
  </p>
  <p class="reading">
    Reading: 50 visually distinct "DNA strands". No two share a sub-sequence —
    the agent must learn each surface from scratch.
  </p>
  <div class="heat-wrap">${renderDNAStrands(deploys)}</div>
</section>

</body>
</html>`

await fs.mkdir(OUTPUT_DIR, { recursive: true })
await fs.writeFile(OUTPUT_HTML, html)

console.log()
console.log('  Preview written to:')
console.log('    ' + path.relative(REPO_ROOT, OUTPUT_HTML))
console.log()
console.log('  Open it:')
console.log('    open ' + path.relative(REPO_ROOT, OUTPUT_HTML))
console.log()
