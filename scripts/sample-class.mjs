// Runs the real PolyRange generator pipeline N times for one class,
// saving each sample's theme + scenario + chrome + rendered home page.
// No Fly, no Docker — just LLM calls, all output local.
//
// Used for blog-post diversity visuals.
//
// Usage:
//   node scripts/sample-class.mjs --class=wstg-sqli-4.7.5.4 --count=20 \
//       --output=samples/sqli-diversity --concurrency=3

import fs from 'node:fs/promises'
import path from 'node:path'
import crypto from 'node:crypto'
import { loadDotEnv } from '../lib/precheck.mjs'

await loadDotEnv(process.cwd())

const { generateTheme } = await import('../generator/generate-theme.mjs')
const { generateScenarioForClass } = await import('../generator/generate-scenario.mjs')
const { generateChrome } = await import('../generator/generate-chrome.mjs')

const args = Object.fromEntries(
  process.argv.slice(2).map(a => {
    const [k, v] = a.replace(/^--/, '').split('=')
    return [k, v ?? true]
  })
)

const REPO_ROOT = process.cwd()
const classId = args.class
const count = parseInt(args.count ?? '20', 10)
const concurrency = Math.max(1, parseInt(args.concurrency ?? '3', 10))
const outputDir = path.resolve(REPO_ROOT, args.output ?? `samples/${classId}`)

if (!classId) { console.error('--class=wstg-... is required'); process.exit(1) }

const classDir = path.join(REPO_ROOT, 'classes', classId)
try { await fs.access(classDir) } catch {
  console.error(`Class directory not found: ${classDir}`)
  process.exit(1)
}

await fs.mkdir(outputDir, { recursive: true })

const indexPath = path.join(outputDir, 'index.json')

const hex = (n) => Array.from(crypto.randomBytes(n), b => b.toString(16).padStart(2, '0')).join('')
const makeCanary = () => 'pr_' + hex(12)

console.log('━'.repeat(72))
console.log(`PolyRange sample run — ${classId}`)
console.log('━'.repeat(72))
console.log(`  Count:        ${count}`)
console.log(`  Concurrency:  ${concurrency}`)
console.log(`  Output:       ${path.relative(REPO_ROOT, outputDir)}`)
console.log(`  Estimated $:  ~$${(count * 1.0).toFixed(0)} (theme + scenario + chrome × ${count})`)
console.log()

const startedAt = Date.now()
const samples = []
const queue = Array.from({ length: count }, (_, i) => i + 1)
let inFlight = 0
let completed = 0
let failures = 0

await new Promise((resolve) => {
  const launch = () => {
    while (inFlight < concurrency && queue.length > 0) {
      const i = queue.shift()
      inFlight++
      runOne(i).then((res) => {
        inFlight--
        completed++
        if (res.error) {
          failures++
          console.log(`  [${completed}/${count}] xx  sample ${String(i).padStart(3, '0')} — ${res.error}`)
        } else {
          samples.push(res.summary)
          console.log(`  [${completed}/${count}] ok  sample ${String(i).padStart(3, '0')}  ${res.summary.siteName}  (${res.summary.endpoint}?${res.summary.slot}=)`)
        }
        if (queue.length === 0 && inFlight === 0) resolve()
        else launch()
      })
    }
  }
  launch()
})

const wallSec = ((Date.now() - startedAt) / 1000).toFixed(1)

await fs.writeFile(indexPath, JSON.stringify({
  classId,
  count,
  completed: samples.length,
  failures,
  wallSeconds: parseFloat(wallSec),
  generatedAt: new Date().toISOString(),
  samples: samples.sort((a, b) => a.id.localeCompare(b.id)),
}, null, 2))

console.log()
console.log('━'.repeat(72))
console.log(`Sample run complete in ${wallSec}s`)
console.log(`  ✓ generated:  ${samples.length} / ${count}`)
console.log(`  ✗ failed:     ${failures}`)
console.log(`  Index JSON:   ${path.relative(REPO_ROOT, indexPath)}`)
console.log()
console.log(`Next: render screenshots and the preview HTML`)
console.log(`  node scripts/render-samples.mjs --input=${path.relative(REPO_ROOT, outputDir)}`)
console.log('━'.repeat(72))


// ── runOne ─────────────────────────────────────────────────────────────────

async function runOne(i) {
  const id = String(i).padStart(3, '0')
  const dir = path.join(outputDir, id)
  await fs.mkdir(dir, { recursive: true })
  const canary = makeCanary()
  try {
    const theme = await generateTheme()
    const scenario = await generateScenarioForClass(theme, classDir, canary)
    let chrome = await generateChrome(theme, scenario.chromeInjection)
    chrome = ensureChromeInjection(chrome, scenario.chromeInjection)
    if (!chrome.includes('{BODY}')) {
      throw new Error('chrome missing {BODY}')
    }

    // Render home page: chrome with a discreet pre-search placeholder
    // body. Keeps the visual close to what a real first visit looks like.
    const placeholderBody = scenario.body
      ? scenario.body.replace('{RESULTS}', `<div style="padding:40px 24px;color:rgba(0,0,0,0.5);font-size:14px">Enter a ${escapeHtml(scenario.featureLabel || 'search')} term to begin.</div>`)
      : `<main style="padding:40px 24px;font-size:14px;color:rgba(0,0,0,0.5)">Welcome.</main>`
    const home = chrome.replace('{BODY}', placeholderBody)

    await fs.writeFile(path.join(dir, 'theme.json'),    JSON.stringify(theme, null, 2))
    await fs.writeFile(path.join(dir, 'scenario.json'), JSON.stringify(scenario, null, 2))
    await fs.writeFile(path.join(dir, 'chrome.html'),   chrome)
    await fs.writeFile(path.join(dir, 'home.html'),     home)

    return {
      summary: {
        id,
        siteName:        theme.siteName,
        industry:        theme.industry,
        font:            theme.font,
        primaryColor:    theme.primaryColor,
        endpoint:        scenario.endpoint?.path || '',
        method:          scenario.endpoint?.method || 'GET',
        slot:            scenario.slots?.user_input?.name || '',
        slotLocation:    scenario.slots?.user_input?.location || '',
        itemsTable:      scenario.itemsTable || null,
        sensitiveTable:  scenario.sensitiveTable || null,
        decoyTableCount: Array.isArray(scenario.decoyTables) ? scenario.decoyTables.length : 0,
        featureLabel:    scenario.featureLabel || '',
        canary,
      },
    }
  } catch (e) {
    return { error: (e.message || String(e)).slice(0, 200) }
  }
}

function ensureChromeInjection(chrome, injection) {
  if (!injection?.html) return chrome
  const hrefMatch = injection.html.match(/(?:href|src|action)=["']([^"']+)["']/)
  const probe = hrefMatch ? hrefMatch[1] : injection.html.replace(/<[^>]+>/g, '').trim().slice(0, 20)
  if (probe && chrome.includes(probe)) return chrome
  const frag = injection.html
  if (chrome.includes('</footer>')) return chrome.replace('</footer>', `${frag}\n</footer>`)
  if (chrome.includes('{BODY}'))    return chrome.replace('{BODY}', `${frag}\n{BODY}`)
  if (chrome.includes('</body>'))   return chrome.replace('</body>', `${frag}\n</body>`)
  return chrome + frag
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}
