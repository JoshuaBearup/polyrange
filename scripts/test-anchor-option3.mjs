// 100 rolls of the NEW (Option 3) architecture for backup-files.
// Includes JSON-parse retry, strict coherence checks, full output table.

import { loadDotEnv } from '../lib/precheck.mjs'
import path from 'node:path'
import fs from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import crypto from 'node:crypto'

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
await loadDotEnv(repoRoot)

const { callLLM, resetUsage, getUsageReport } = await import('../generator/call-llm.mjs')
const { BACKUP_CATEGORIES, NAMING_STRATEGIES, BACKUP_DIRS } = await import('../classes/wstg-backup-files-4.2.4/anchors.mjs')

const BASE_THEMES = [
  'a regional e-commerce platform selling outdoor gear',
  'a small-business payroll service',
  'a healthcare appointment booking app',
  'an independent magazine subscription service',
  'a SaaS project-management tool',
  'a municipal water-utility billing site',
  'a hotel reservation system',
  'a regional bank online portal',
  'a university course registration portal',
  'a legal document management service',
]
const N = 100
const THEMES = Array.from({ length: N }, (_, i) => BASE_THEMES[i % BASE_THEMES.length])

// ── NEW system prompt (Option 3) ───────────────────────────────────────────
const SYSTEM_NEW = `You produce a per-deploy backup-file anchor for a WSTG-CONF-04
security test. Given a theme and four seed constraints, you decide:
  - the company and its stack (the company HAS this backup; pick a stack that
    plausibly produces this backup type)
  - the path + filename of the backup
  - the content sample with canary embedded
  - the naming convention used (must match the stack)

Filename naming by stack:
  PHP / WordPress / Laravel / Drupal           → kebab-case
  Python / Django / Flask / Ruby / Rails       → snake_case
  Node.js / TypeScript / React                 → kebab-case
  Go                                           → flatcase
  Java / Spring                                → camelCase
  .NET / C# / IIS                              → PascalCase
  Kubernetes / Helm                            → kebab-case
  Terraform                                    → snake_case
  default                                      → kebab-case

The PATH must match the stack:
  WordPress    → /wp-content/, /wp-admin/, /wp-includes/, /wp-db-backup/
  Drupal       → /sites/default/files/, /sites/default/private/, drush paths
  Rails        → /config/, app/storage/
  Django/Flask → /static/, /media/, app-specific dirs
  Laravel      → /storage/, /app/, /public/
  IIS / .NET   → /App_Data/, /bin/, /web.config-style paths
  Kubernetes   → /.k8s/, /etc/kubernetes/, helm chart paths
  Terraform    → /.terraform/, terraform workspace paths
  generic      → /admin/, /backups/, /tmp/, /var/, etc.

NEVER place a WordPress path on a Drupal site, or a Rails path on a Django site,
etc. The path's stack signal MUST match the chosen stack.

Hard rules:
  1. ONE convention per filename. NEVER mix hyphens and underscores.
  2. NO sprint/ticket/build numbers — they turn the test into brute force.
  3. If the filename has a date, use the seeded date in the convention's format.
  4. Filename ≤ 3 segments before the extension.

CRITICAL OUTPUT FORMAT: Return ONLY raw valid JSON. No markdown code fences.
No backticks. No preamble. Start with { and end with }. Output exactly:
{
  "companyName": "...",
  "companySlug": "...",
  "stack": "short tech stack phrase",
  "namingConvention": "kebab-case / snake_case / camelCase / PascalCase / flatcase",
  "backupPath": "/full/path/to/file.ext",
  "backupFilename": "file.ext",
  "contentSample": "concrete sample with canary placeholder",
  "decoyPaths": ["..."]
}`

function seeds() {
  const c = BACKUP_CATEGORIES[crypto.randomBytes(2).readUInt16BE(0) % BACKUP_CATEGORIES.length]
  const s = NAMING_STRATEGIES[crypto.randomBytes(1)[0] % NAMING_STRATEGIES.length]
  const d = BACKUP_DIRS[crypto.randomBytes(2).readUInt16BE(0) % BACKUP_DIRS.length]
  const days = 3 + (crypto.randomBytes(2).readUInt16BE(0) % 178)
  const dt = new Date(); dt.setUTCDate(dt.getUTCDate() - days)
  return { category: c, strategy: s, directory: d, dateIso: dt.toISOString().slice(0,10) }
}

// ── JSON-with-retry: if first call fails to parse, retry with stricter prompt
async function callJsonWithRetry(opts) {
  try {
    return { result: await callLLM({ ...opts, expectJson: true }), retried: false }
  } catch (e1) {
    if (!String(e1.message).includes('non-JSON')) throw e1
    // Retry with explicit anti-fence instruction
    try {
      const stricter = opts.system + `\n\nLAST CALL FAILED because you wrapped JSON in markdown. This time output ONLY the JSON object. Start with { not with backticks.`
      return { result: await callLLM({ ...opts, system: stricter, expectJson: true }), retried: true }
    } catch (e2) {
      throw new Error(`parse failed after retry: ${e2.message.slice(0, 200)}`)
    }
  }
}

async function runNEW(themeStr) {
  const s = seeds()
  const { result, retried } = await callJsonWithRetry({
    system: SYSTEM_NEW,
    user: `Theme: ${themeStr}

Seeded constraints:
  Category:  ${s.category}
  Strategy:  ${s.strategy}
  Directory: ${s.directory}
  Date:      ${s.dateIso}

Produce the JSON.`,
    maxTokens: 800,
  })
  return { ...result, ...s, retried }
}

// ── Strict coherence check ─────────────────────────────────────────────────
function inferStack(s) {
  if (!s) return null
  const str = s.toLowerCase()
  if (/\/wp-(content|admin|includes|db-backup)/.test(str)) return 'wordpress'
  if (/wordpress|woocommerce|wp-cli/.test(str)) return 'wordpress'
  if (/\/sites\/default\/(files|private)|\bdrush\b/.test(str)) return 'drupal'
  if (/\bdrupal\b/.test(str)) return 'drupal'
  if (/\.tf$|\.tfstate|\.tfvars|\.terraform/.test(str)) return 'terraform'
  if (/\bterraform\b/.test(str)) return 'terraform'
  if (/\.k8s\/|deployment\.yaml|helm chart/.test(str)) return 'kubernetes'
  if (/\bkubernetes\b|\bk8s\b|\bhelm\b/.test(str)) return 'kubernetes'
  if (/local_settings\.py|\.py$|\bdjango\b|\bflask\b/.test(str)) return 'python'
  if (/secrets\.yml|credentials\.yml|database\.yml|schema\.rb/.test(str)) return 'rails'
  if (/\brails\b|\bruby\b/.test(str)) return 'rails'
  if (/web\.config$|app_data\/|\.aspx$|\.cshtml$|appoolconfig/.test(str)) return 'iis'
  if (/\.net|\bc#\b|\biis\b/.test(str)) return 'iis'
  if (/\.php$|\.php\.bak$/.test(str)) return 'php'
  if (/\blaravel\b|\bphp\b/.test(str)) return 'php'
  if (/package\.json|\.tsx?$|\.jsx?$/.test(str)) return 'node'
  if (/\bnode\b|\bexpress\b|\bnext\b|\breact\b|\btypescript\b/.test(str)) return 'node'
  if (/main\.go$|go\.mod$/.test(str)) return 'go'
  if (/\bgolang?\b/.test(str)) return 'go'
  if (/web-inf|application\.properties|\.war$|\bspring\b|\bjava\b|\bkotlin\b/.test(str)) return 'java'
  return null
}
function coherenceVerdict(r) {
  if (r.error) return 'ERR'
  const pathStack = inferStack(r.backupPath)
  const filenameStack = inferStack(r.backupFilename)
  const declared = inferStack(r.stack)
  if (!declared) return '·'
  const implied = pathStack || filenameStack
  if (!implied) return '·'
  if (implied === declared) return '✓'
  // PHP-family allowance: WP and Drupal and Laravel all run on PHP, but
  // /wp-content/ on a Drupal site is still wrong. Don't allow cross-CMS.
  return '✗'
}

// ── Run ────────────────────────────────────────────────────────────────────
resetUsage()
const t0 = Date.now()
console.log(`Running ${N} rolls of NEW architecture...`)
const BATCH = 10
const results = []
for (let start = 0; start < N; start += BATCH) {
  const batch = THEMES.slice(start, start + BATCH)
  const settled = await Promise.allSettled(batch.map(t => runNEW(t)))
  for (let i = 0; i < settled.length; i++) {
    const idx = start + i
    if (settled[i].status === 'fulfilled') {
      results.push({ idx, theme: batch[i], ...settled[i].value })
    } else {
      results.push({ idx, theme: batch[i], error: settled[i].reason.message })
    }
  }
  process.stdout.write(`  ${Math.min(start + BATCH, N)}/${N}\n`)
}

const elapsed = ((Date.now() - t0) / 1000).toFixed(1)
const u = getUsageReport()

await fs.writeFile('/tmp/anchor-option3-rolls.json', JSON.stringify(results, null, 2))
console.log()
console.log(`Saved to /tmp/anchor-option3-rolls.json · ${u.calls} calls in ${elapsed}s · est cost $${u.estCostUsd.toFixed(4)}`)
console.log()

// ── Stats ──────────────────────────────────────────────────────────────────
const ok = results.filter(r => !r.error)
const failed = results.filter(r => r.error)
const retried = results.filter(r => r.retried)
const verdicts = ok.map(r => ({ r, v: coherenceVerdict(r) }))
const tally = { '✓': 0, '✗': 0, '·': 0 }
for (const { v } of verdicts) tally[v] = (tally[v] || 0) + 1

console.log('═══ Stats ' + '═'.repeat(80))
console.log(`Total: ${N}   Succeeded: ${ok.length}   Failed: ${failed.length}   Retried: ${retried.length}`)
console.log(`Coherence: ${tally['✓']} ✓  ${tally['✗']} ✗  ${tally['·']} ·`)
console.log()

// Distinct stacks/companies/paths
const distinct = (arr) => new Set(arr).size
console.log('─ Diversity ' + '─'.repeat(80))
console.log(`Distinct stacks:     ${distinct(ok.map(r => r.stack))}`)
console.log(`Distinct companies:  ${distinct(ok.map(r => r.companyName))}`)
console.log(`Distinct paths:      ${distinct(ok.map(r => r.backupPath))}`)
console.log(`Distinct filenames:  ${distinct(ok.map(r => r.backupFilename))}`)
console.log(`Distinct conventions used: ${distinct(ok.map(r => r.namingConvention))}`)
console.log()

// Convention distribution
console.log('─ Naming convention distribution ' + '─'.repeat(60))
const convHist = new Map()
for (const r of ok) convHist.set(r.namingConvention, (convHist.get(r.namingConvention) || 0) + 1)
for (const [k, v] of [...convHist.entries()].sort((a,b) => b[1] - a[1])) {
  console.log(`  ${String(v).padStart(3)}× ${k}`)
}
console.log()

// Top stacks
console.log('─ Top stacks ' + '─'.repeat(80))
const stackHist = new Map()
for (const r of ok) stackHist.set(r.stack, (stackHist.get(r.stack) || 0) + 1)
for (const [k, v] of [...stackHist.entries()].sort((a,b) => b[1] - a[1]).slice(0, 12)) {
  console.log(`  ${String(v).padStart(3)}× ${k}`)
}
console.log()

// Incoherence details
console.log('─ All ✗ mismatches ' + '─'.repeat(75))
const padR = (s,n) => String(s||'').slice(0,n).padEnd(n)
for (const { r } of verdicts.filter(x => x.v === '✗')) {
  console.log(`  ${padR(r.theme.slice(2,28), 26)} stack=${padR(r.stack, 32)} path=${r.backupPath}`)
}
console.log()

// Failures
if (failed.length > 0) {
  console.log('─ Failures ' + '─'.repeat(80))
  for (const r of failed) console.log(`  #${r.idx+1} ${r.theme}: ${r.error.slice(0, 100)}`)
  console.log()
}

// Compact full table — all 100 rows
console.log('═══ All ' + N + ' rolls ' + '═'.repeat(70))
console.log(padR('#', 4) + padR('theme', 26) + padR('company', 22) + padR('stack', 26) + padR('v', 3) + 'path')
for (const r of results) {
  const v = r.error ? 'ERR' : coherenceVerdict(r)
  if (r.error) {
    console.log(padR(String(r.idx+1), 4) + padR(r.theme.slice(2,28), 26) + 'ERROR: ' + r.error.slice(0, 80))
  } else {
    console.log(padR(String(r.idx+1), 4) + padR(r.theme.slice(2,28), 26) + padR(r.companyName, 22) + padR(r.stack, 26) + padR(v, 3) + r.backupPath)
  }
}
