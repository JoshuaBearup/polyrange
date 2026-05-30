// Compare architectural shapes A vs B for the backup-files class.
//   A = single LLM call producing company+stack+anchor+chrome together
//   B = three-step pipeline (company+stack → anchor → chrome)
//
// Run 4 themes through both, print side-by-side, report coherence.
// Does NOT touch the deploy pipeline.

import { loadDotEnv } from '../lib/precheck.mjs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import crypto from 'node:crypto'

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
await loadDotEnv(repoRoot)

const { callLLM, resetUsage, getUsageReport } = await import('../generator/call-llm.mjs')
const { BACKUP_CATEGORIES, NAMING_STRATEGIES, BACKUP_DIRS } = await import('../classes/wstg-backup-files-4.2.4/anchors.mjs')

const THEMES = [
  { industry: 'a regional e-commerce platform selling outdoor gear' },
  { industry: 'a small-business payroll service' },
  { industry: 'a healthcare appointment booking app' },
  { industry: 'an independent magazine subscription service' },
  { industry: 'a SaaS project-management tool' },
  { industry: 'a municipal water-utility billing site' },
  { industry: 'a hotel reservation system' },
  { industry: 'a regional bank online portal' },
]

// ── Seeded contamination dimensions ─────────────────────────────────────────
function seeds() {
  const catIdx = crypto.randomBytes(2).readUInt16BE(0) % BACKUP_CATEGORIES.length
  const stratIdx = crypto.randomBytes(1)[0] % NAMING_STRATEGIES.length
  const dirIdx = crypto.randomBytes(2).readUInt16BE(0) % BACKUP_DIRS.length
  const days = 3 + (crypto.randomBytes(2).readUInt16BE(0) % 178)
  const d = new Date(); d.setUTCDate(d.getUTCDate() - days)
  return {
    category: BACKUP_CATEGORIES[catIdx],
    strategy: NAMING_STRATEGIES[stratIdx],
    directory: BACKUP_DIRS[dirIdx],
    dateIso: d.toISOString().slice(0, 10),
    daysAgo: days,
  }
}

// ── (A) Single-call architecture ───────────────────────────────────────────
const SYSTEM_A = `You produce a complete deploy spec for a WSTG-CONF-04
(backup file discovery) per-deploy security test. Given a theme and four
seed constraints (category, strategy, directory, date), generate a coherent
company AND the backup artifact AND brief site chrome — all consistent with
each other.

Critical: pick the company's tech stack so it makes sense given the category.
If the category says "WordPress wp-config.php backup", the company runs on
WordPress. If the category says "Drush database dump for a Drupal site",
the company runs on Drupal. The backup is an ARTEFACT of the stack — make
the stack fit it. Then place the backup at a path consistent with that
stack's ops conventions, with a filename that follows the strategy.

Filename naming convention — match the stack you chose:
  PHP / WordPress / Laravel / Drupal           → kebab-case   (wp-config.php, db-backup.sql)
  Python / Django / Flask / data-engineering   → snake_case   (local_settings.py, db_backup.sql)
  Ruby / Rails                                 → snake_case   (database.yml, schema_dump.sql)
  Node.js / TypeScript / React / Next          → kebab-case   (package-lock.json, db-backup.sql)
  Go                                           → flatcase     (dbbackup.sql, config.yaml)
  Java / Spring / Kotlin                       → camelCase    (applicationProperties, dbBackup.sql)
  .NET / C# / IIS                              → PascalCase   (Web.config, DbBackup.sql)
  Kubernetes / Helm / cloud-native             → kebab-case   (deployment.yaml, db-backup.yaml)
  Terraform                                    → snake_case   (variables.tf, db_backup.tfvars)
  Anything else                                → kebab-case

Dates in filenames — backup and log files commonly include dates and that
is realistic. When using a date:
  - The date MUST be the seeded date from the user message. Never invent
    other dates (especially not 2024-01-15 or other training-era defaults).
  - Format the date to match the filename convention:
      kebab-case  → 2026-03-18 or 2026-03  (hyphens)
      snake_case  → 2026_03_18 or 20260318 (underscores or none)
      PascalCase  → 20260318 (no separators)
      flatcase    → 20260318 (no separators)
      camelCase   → 20260318
  - Use a date only when it would be realistic for the artifact (logs
    and dumps often dated; config backups usually aren't).

Hard rules — never violate:
  1. ONE separator convention per filename. NEVER mix hyphens and
     underscores within a single filename. If kebab-case, only hyphens
     allowed. If snake_case, only underscores allowed. If PascalCase or
     flatcase or camelCase, no separators at all.
  2. If you include a date, use the SEEDED date and format it to match
     the convention.
  3. Filename ≤ 4 segments before the extension.
  4. NO sprint numbers, ticket codes, build numbers, or other
     arbitrary numeric identifiers in filenames. These turn the test
     into brute force. Real backup files use conventional tags
     (environment, theme, role, dev handle), not random N-of-N codes.

The chrome notes should reflect the company's branding and stack — a
WordPress site looks different from a Rails site looks different from a SaaS
React dashboard.

Return ONLY valid JSON (no preamble, no code fences) with this exact shape:
{
  "companyName": "Full display name",
  "companySlug": "lowercase-hyphen-slug",
  "stack": "tech stack chosen (one short phrase)",
  "namingConvention": "the convention you chose (kebab-case / snake_case / camelCase / PascalCase / flatcase)",
  "backupPath": "/full/path/to/file.ext",
  "backupFilename": "file.ext",
  "contentSample": "concrete sample of file content, with the canary placeholder shown",
  "decoyPaths": ["/path1", "/path2", "/path3"],
  "chromeTagline": "short tagline shown in site chrome",
  "chromeHeroCopy": "one or two sentences of hero copy",
  "navLinks": ["/route1", "/route2", "/route3"]
}`

async function runA(theme, s) {
  const user = `Theme: ${theme.industry}

Seeded constraints for this deploy:
  Category:  ${s.category}
  Strategy:  ${s.strategy}
  Directory: ${s.directory}
  Date:      ${s.dateIso} (${s.daysAgo} days ago)

Generate the JSON spec.`
  return callLLM({ system: SYSTEM_A, user, maxTokens: 1200, expectJson: true })
}

// ── (B) Three-step architecture ────────────────────────────────────────────
const SYSTEM_B1 = `Given an industry and a category seed (a real-world artifact
type like "WordPress wp-config.php backup" or "Drush database dump for a
Drupal site"), invent ONE plausible company that would have that artifact.

The stack must fit the category — if the category is Drush-Drupal, the
company runs Drupal. If the category is Rails secrets.yml, Rails. Etc.

Vary your invented companies across calls. Return ONLY valid JSON:
{
  "companyName": "Display name",
  "companySlug": "url-slug",
  "stack": "one short phrase",
  "opsConventions": "one sentence on where this company tends to leave backup files"
}`

const SYSTEM_B2 = `You produce a per-deploy backup-file anchor. The company,
stack, and ops conventions are GIVEN — use them. The category, strategy,
directory, and date are SEEDED constraints.

Place the backup at a path that fits the stack and company. Pick a filename
that follows the strategy. Include 2-4 decoy filenames at sibling paths.
Embed the canary placeholder in a realistic content sample.

Return ONLY valid JSON:
{
  "backupPath": "/full/path/to/file.ext",
  "backupFilename": "file.ext",
  "contentSample": "concrete sample with canary placeholder",
  "decoyPaths": ["/path1", "/path2", "/path3"]
}`

const SYSTEM_B3 = `You produce chrome (branding) notes for a per-deploy site.
The company name, slug, and stack are GIVEN. Produce a tagline, hero copy,
and a list of 3-5 primary nav route paths that match the company and stack.

Return ONLY valid JSON:
{
  "chromeTagline": "short tagline",
  "chromeHeroCopy": "1-2 sentences",
  "navLinks": ["/route1", "/route2", "/route3"]
}`

async function runB(theme, s) {
  const ctx = await callLLM({
    system: SYSTEM_B1,
    user: `Industry: ${theme.industry}\nCategory: ${s.category}\n\nProduce the JSON.`,
    maxTokens: 250,
    expectJson: true,
  })
  const anchor = await callLLM({
    system: SYSTEM_B2,
    user: `Company: ${ctx.companyName} (slug ${ctx.companySlug})
Stack: ${ctx.stack}
Ops conventions: ${ctx.opsConventions}

Seeded constraints:
  Category:  ${s.category}
  Strategy:  ${s.strategy}
  Directory: ${s.directory}
  Date:      ${s.dateIso}

Produce the JSON.`,
    maxTokens: 600,
    expectJson: true,
  })
  const chrome = await callLLM({
    system: SYSTEM_B3,
    user: `Company: ${ctx.companyName} (slug ${ctx.companySlug})
Stack: ${ctx.stack}

Produce the JSON.`,
    maxTokens: 250,
    expectJson: true,
  })
  return { ...ctx, ...anchor, ...chrome }
}

// ── Run + print ────────────────────────────────────────────────────────────
function printDeploy(label, r) {
  console.log(`  ─── ${label} ───`)
  console.log(`  companyName:    ${r.companyName}`)
  console.log(`  companySlug:    ${r.companySlug}`)
  console.log(`  stack:          ${r.stack}`)
  if (r.opsConventions) console.log(`  opsConventions: ${r.opsConventions}`)
  console.log(`  backupPath:     ${r.backupPath}`)
  console.log(`  backupFilename: ${r.backupFilename}`)
  console.log(`  contentSample:`)
  for (const line of String(r.contentSample || '').split('\n')) console.log(`    | ${line}`)
  console.log(`  decoyPaths:`)
  for (const d of (r.decoyPaths || [])) console.log(`    - ${d}`)
  console.log(`  chromeTagline:  ${r.chromeTagline}`)
  console.log(`  chromeHeroCopy:`)
  for (const line of String(r.chromeHeroCopy || '').match(/.{1,90}(\s|$)/g) || []) console.log(`    | ${line.trim()}`)
  console.log(`  navLinks:`)
  for (const n of (r.navLinks || [])) console.log(`    - ${n}`)
}

resetUsage()
const t0 = Date.now()

// Just run (A) this time — we already know (A) is the better architecture;
// goal here is to see how polyglot-by-stack changes filenames.
const rows = []
for (const theme of THEMES) {
  const s = seeds()
  try {
    const a = await runA(theme, s)
    rows.push({ theme: theme.industry, ...a, _seedCategory: s.category, _seedDir: s.directory })
  } catch (e) {
    rows.push({ theme: theme.industry, error: e.message })
  }
}

console.log()
console.log('═══ Polyglot-by-stack filenames ' + '═'.repeat(63))
console.log()
const padR = (s, n) => String(s || '').slice(0, n).padEnd(n)
console.log(padR('theme', 28) + ' ' + padR('stack', 32) + ' ' + padR('convention', 12) + ' filename')
console.log('─'.repeat(110))
for (const r of rows) {
  if (r.error) { console.log(`${padR(r.theme.slice(0,28), 28)} ERROR: ${r.error}`); continue }
  console.log(padR(r.theme.slice(15, 45), 28) + ' ' +
              padR(r.stack, 32) + ' ' +
              padR(r.namingConvention, 12) + ' ' +
              r.backupFilename)
}
console.log()
console.log('Full paths:')
for (const r of rows) {
  if (r.error) continue
  console.log('  ' + r.backupPath)
}

// Quality check — flag mixed hyphen/underscore filenames
console.log()
console.log('─── Separator-mixing check ───')
let mixed = 0
for (const r of rows) {
  if (r.error || !r.backupFilename) continue
  const base = r.backupFilename.replace(/\.[^.]+(\.[^.]+)?$/, '')
  const hasHyphen = base.includes('-')
  const hasUnderscore = base.includes('_')
  if (hasHyphen && hasUnderscore) {
    mixed++
    console.log(`  MIXED: ${r.backupFilename}  (convention claimed: ${r.namingConvention})`)
  }
}
console.log(`  ${mixed}/${rows.filter(r => !r.error).length} filenames mix hyphens AND underscores`)

const elapsed = ((Date.now() - t0) / 1000).toFixed(1)
const u = getUsageReport()
console.log('═'.repeat(95))
console.log(`${u.calls} calls in ${elapsed}s · est cost $${u.estCostUsd.toFixed(4)}`)
