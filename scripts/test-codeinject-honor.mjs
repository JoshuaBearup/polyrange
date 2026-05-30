// Test whether the code-injection scenario LLM honors the anchor's
// language pick. Pin via POLYRANGE_LANG, generate, compare.

import { loadDotEnv } from '../lib/precheck.mjs'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
await loadDotEnv(repoRoot)

const { generateScenarioForClass } = await import('../generator/generate-scenario.mjs')
const { resetUsage, getUsageReport } = await import('../generator/call-llm.mjs')

const classDir = path.resolve(repoRoot, 'classes/wstg-code-injection-4.7.11')
const LANGS = ['python', 'php', 'ruby', 'node']
const PER_LANG = 5

const stubTheme = (tag) => ({
  industryVertical: 'e-commerce',
  era: '2020s modern startup',
  maturity: 'venture-backed startup with ~30 employees',
  voice: 'utilitarian and no-nonsense',
  layoutArchetype: 'top horizontal nav bar, wide content area below',
  designLanguage: 'flat design',
  colorTreatment: 'light mode, muted and restrained',
  colorFamily: 'blue',
  brandName: `TestCo-${tag}`,
  productConcept: 'a sample analytics dashboard with a formula field',
})

resetUsage()
const t0 = Date.now()
const results = []

for (const pinned of LANGS) {
  process.env.POLYRANGE_LANG = pinned
  for (let i = 0; i < PER_LANG; i++) {
    const canary = `pr_${crypto.randomBytes(5).toString('hex')}`
    const theme = stubTheme(`${pinned}-${i}`)
    process.stdout.write(`[${pinned} ${i + 1}/${PER_LANG}] `)
    try {
      const scenario = await generateScenarioForClass(theme, classDir, canary)
      const ok = scenario.language === pinned
      results.push({ pinned, got: scenario.language, honored: ok })
      process.stdout.write(ok ? `✓ ${scenario.language}\n` : `✗ got ${scenario.language}\n`)
    } catch (e) {
      results.push({ pinned, got: null, honored: false, error: e.message })
      process.stdout.write(`ERR\n`)
    }
  }
}

const elapsed = ((Date.now() - t0) / 1000).toFixed(1)
const u = getUsageReport()

console.log()
console.log('═══ Honor rate by pinned language ═══')
for (const lang of LANGS) {
  const rows = results.filter(r => r.pinned === lang)
  const honored = rows.filter(r => r.honored).length
  console.log(`  ${lang.padEnd(8)} ${honored}/${rows.length} honored`)
  const drift = rows.filter(r => !r.honored && r.got)
  if (drift.length > 0) {
    for (const d of drift) console.log(`    drift: anchor=${d.pinned} got=${d.got}`)
  }
}
console.log()
console.log(`Overall: ${results.filter(r => r.honored).length}/${results.length} honored`)
console.log(`Time: ${elapsed}s · ${u.calls} calls · est cost $${u.estCostUsd.toFixed(4)}`)
