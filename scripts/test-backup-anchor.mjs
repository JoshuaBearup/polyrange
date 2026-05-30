// Roll the LLM-driven anchor generator for wstg-backup-files-4.2.4 100 times
// and report distribution stats — category/strategy/date coverage, filename
// segment counts, same-category filename collisions, generic-name detection.

import { loadDotEnv } from '../lib/precheck.mjs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
await loadDotEnv(repoRoot)

const { generateAnchor, BACKUP_CATEGORIES, NAMING_STRATEGIES, BACKUP_DIRS } = await import('../classes/wstg-backup-files-4.2.4/anchors.mjs')
const { callLLM, resetUsage, getUsageReport } = await import('../generator/call-llm.mjs')

// 12 base themes rotated 9× to reach 100
const BASE_THEMES = [
  { industry: 'a regional e-commerce platform selling outdoor gear' },
  { industry: 'a freight-and-logistics shipment tracking dashboard' },
  { industry: 'a small-business payroll service' },
  { industry: 'a university course registration portal' },
  { industry: 'a healthcare appointment booking app' },
  { industry: 'a SaaS project-management tool' },
  { industry: 'a municipal water-utility billing site' },
  { industry: 'an independent magazine subscription service' },
  { industry: 'a hotel reservation system' },
  { industry: 'a regional bank online portal' },
  { industry: 'an enterprise CRM dashboard' },
  { industry: 'a public transit fare management site' },
]
const N = 100
const THEMES = Array.from({ length: N }, (_, i) => BASE_THEMES[i % BASE_THEMES.length])

resetUsage()
const t0 = Date.now()

// Parse the first backtick-quoted string from the anchor (the path)
function extractPath(anchor) {
  const m = anchor.match(/`([^`]+)`/)
  return m ? m[1] : null
}
function extractFilename(p) {
  if (!p) return null
  const parts = p.split('/')
  return parts[parts.length - 1] || null
}
function segmentCount(filename) {
  if (!filename) return 0
  // Strip the last extension only — "wp-config.php.bak" → segments "wp,config", ext ".php.bak"
  // For our purposes count hyphen/underscore/dot separators in the base
  const base = filename.replace(/\.(sql|csv|json|jsonl|ndjson|tsv|txt|log|xml|yaml|yml|conf|config|bak|old|env|env\.\w+|tar|gz|zip|php|py|rb|tfstate|dump|har|md5)(\..*)?$/i, '')
  return base.split(/[-_.]/).filter(Boolean).length
}
function looksGeneric(filename) {
  if (!filename) return false
  const generic = /^(backup|dump|database|db|prod|staging|export|backup_prod|backup_staging|backup_db|sqldump|wordpress|drupal|users|customers|orders|admin)\.(sql|csv|json|jsonl|txt|log|env|conf|bak|gz|zip|tar)$/i
  return generic.test(filename)
}

// Run in batches of 10 to parallelise without hammering the API
const BATCH = 10
const results = []
for (let start = 0; start < N; start += BATCH) {
  const batch = THEMES.slice(start, start + BATCH)
  const settled = await Promise.allSettled(
    batch.map(theme => generateAnchor({ callLLM, theme }))
  )
  for (let i = 0; i < settled.length; i++) {
    const idx = start + i
    if (settled[i].status === 'fulfilled') {
      const r = settled[i].value
      const path = extractPath(r.anchor)
      const filename = extractFilename(path)
      results.push({ idx, theme: batch[i].industry, ...r, path, filename, segments: segmentCount(filename), generic: looksGeneric(filename) })
    } else {
      results.push({ idx, theme: batch[i].industry, error: settled[i].reason.message })
    }
  }
  process.stdout.write(`${Math.min(start + BATCH, N)}/${N} `)
}
console.log('\n')

// Persist full results so they can be inspected without re-running
import fs from 'node:fs/promises'
await fs.writeFile('/tmp/backup-anchor-rolls.json', JSON.stringify(results, null, 2))
console.log('Full results saved to /tmp/backup-anchor-rolls.json')
console.log()

// Compact one-line view of all 100
const shortCat = (c) => c.split(',')[0].slice(0, 38).padEnd(38)
const shortStrat = (s) => {
  if (s.startsWith('use the tag')) return 'cat-default'
  if (s.startsWith('REPLACE') && s.includes('theme')) return 'theme       '
  if (s.startsWith('REPLACE') && s.includes('build')) return 'build/ticket'
  if (s.startsWith('REPLACE') && s.includes('developer')) return 'dev-handle  '
  if (s.startsWith('OMIT')) return 'OMIT/bare   '
  return s.slice(0, 12)
}
console.log('═══ All 100 rolls ' + '═'.repeat(73))
console.log('#    cat                              strat       seeded-dir            -> actual path')
for (const r of results) {
  if (r.error) { console.log(`${String(r.idx + 1).padStart(3)}  ERROR: ${r.error.slice(0, 80)}`); continue }
  const sd = (r.directory || '').slice(0, 22).padEnd(22)
  console.log(`${String(r.idx + 1).padStart(3)}  ${shortCat(r.category).slice(0,30).padEnd(30)} ${shortStrat(r.strategy)} ${sd} -> ${r.path || '(unparsed)'}`)
}
console.log()

const elapsed = ((Date.now() - t0) / 1000).toFixed(1)

// ── Stats ──────────────────────────────────────────────────────────────────
const ok = results.filter(r => !r.error)
const failed = results.filter(r => r.error)

const distinct = (arr) => new Set(arr.filter(Boolean)).size
const histogram = (arr) => {
  const h = new Map()
  for (const v of arr) h.set(v, (h.get(v) || 0) + 1)
  return [...h.entries()].sort((a, b) => b[1] - a[1])
}

console.log('═══ Stats ' + '═'.repeat(80))
console.log(`Total: ${N}    Succeeded: ${ok.length}    Failed: ${failed.length}    Time: ${elapsed}s`)
console.log()

console.log('─ Categories ' + '─'.repeat(78))
console.log(`Distinct categories drawn: ${distinct(ok.map(r => r.category))} / ${BACKUP_CATEGORIES.length}`)
const catHist = histogram(ok.map(r => r.category))
console.log(`Top 5 by frequency:`)
for (const [c, n] of catHist.slice(0, 5)) console.log(`  ${n}× ${c.slice(0, 90)}`)
console.log(`Bottom (never drawn): ${BACKUP_CATEGORIES.length - distinct(ok.map(r => r.category))}`)
console.log()

console.log('─ Strategies ' + '─'.repeat(78))
console.log(`Distinct strategies drawn: ${distinct(ok.map(r => r.strategy))} / ${NAMING_STRATEGIES.length}`)
for (const [s, n] of histogram(ok.map(r => r.strategy))) console.log(`  ${n}× ${s.slice(0, 90)}`)
console.log()

console.log('─ Filenames ' + '─'.repeat(79))
console.log(`Distinct filenames: ${distinct(ok.map(r => r.filename))} / ${ok.length}`)
console.log(`Distinct paths: ${distinct(ok.map(r => r.path))} / ${ok.length}`)
const segHist = histogram(ok.map(r => r.segments))
console.log(`Segment counts (filename base, excluding extension):`)
for (const [s, n] of segHist.sort((a, b) => a[0] - b[0])) console.log(`  ${s} segments: ${n}× (${Math.round(100 * n / ok.length)}%)`)
const generic = ok.filter(r => r.generic)
console.log(`Generic-looking filenames (e.g. backup.sql, dump.sql): ${generic.length} (${Math.round(100 * generic.length / ok.length)}%)`)
if (generic.length > 0) {
  for (const r of generic.slice(0, 5)) console.log(`  ${r.filename}`)
}
console.log()

console.log('─ Same-category filename collisions ' + '─'.repeat(54))
const byCat = new Map()
for (const r of ok) {
  if (!byCat.has(r.category)) byCat.set(r.category, [])
  byCat.get(r.category).push(r.filename)
}
let totalCollisions = 0
const catsWithCollisions = []
for (const [cat, names] of byCat) {
  if (names.length < 2) continue
  const duped = histogram(names).filter(([, n]) => n > 1)
  if (duped.length > 0) {
    catsWithCollisions.push({ cat, total: names.length, duped })
    for (const [, n] of duped) totalCollisions += n
  }
}
console.log(`Categories with >=2 draws: ${[...byCat.values()].filter(v => v.length >= 2).length}`)
console.log(`Categories with at least one collision: ${catsWithCollisions.length}`)
console.log(`Total colliding generations: ${totalCollisions}`)
if (catsWithCollisions.length > 0) {
  console.log('Examples:')
  for (const c of catsWithCollisions.slice(0, 5)) {
    console.log(`  ${c.cat.slice(0, 70)}`)
    for (const [fn, n] of c.duped) console.log(`    ${n}× ${fn}`)
  }
}
console.log()

console.log('─ Directories (SecLists pool) ' + '─'.repeat(60))
console.log(`Pool size: ${BACKUP_DIRS.length}`)
console.log(`Distinct seeded directories: ${distinct(ok.map(r => r.directory))} / ${ok.length}`)
// Did the LLM actually USE the seeded directory? Compare path-dir to the seed.
const honored = ok.filter(r => {
  if (!r.path || !r.directory) return false
  const dirPart = r.path.slice(0, r.path.lastIndexOf('/') + 1)
  // Tolerant match: the seeded dir appears as a substring of the actual path
  const seedTrim = r.directory.replace(/\/$/, '')
  return r.path.includes(seedTrim)
})
console.log(`Anchors honoring seeded directory: ${honored.length}/${ok.length} (${Math.round(100*honored.length/ok.length)}%)`)
// Top observed dir prefixes from the rendered paths
const obsDirs = ok.map(r => {
  if (!r.path) return null
  return r.path.slice(0, r.path.lastIndexOf('/') + 1)
}).filter(Boolean)
console.log(`Distinct observed full dirs in output: ${distinct(obsDirs)}`)
const obsHist = histogram(obsDirs)
console.log('Top 10 observed dirs:')
for (const [d, n] of obsHist.slice(0, 10)) console.log(`  ${String(n).padStart(3)}× ${d}`)
console.log()

console.log('─ Dates ' + '─'.repeat(82))
console.log(`Distinct jiggle dates: ${distinct(ok.map(r => r.date))} / ${ok.length}`)
console.log(`Date range: ${[...ok.map(r => r.date)].sort()[0]} to ${[...ok.map(r => r.date)].sort().reverse()[0]}`)
console.log()

const u = getUsageReport()
console.log('═══ Usage ' + '═'.repeat(80))
console.log(`${u.calls} calls    in ${u.inputTokens.toLocaleString()} / out ${u.outputTokens.toLocaleString()} tokens    est cost $${u.estCostUsd.toFixed(4)}`)
