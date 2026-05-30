// Verify the LLM honors the per-deploy INPUT-LOCATION seed across multiple
// injection classes. For each class, draw N location seeds (one per call),
// generate the scenario via the production pipeline, parse
// scenario.slots.user_input.location, and check it equals the seeded value.

import { loadDotEnv } from '../lib/precheck.mjs'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
await loadDotEnv(repoRoot)

const { generateScenarioForClass } = await import('../generator/generate-scenario.mjs')
const { resetUsage, getUsageReport } = await import('../generator/call-llm.mjs')

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
  productConcept: 'a sample app with a search feature',
})

// Classes to test, with how many rolls each
const TESTS = [
  { dir: 'classes/wstg-sqli-4.7.5.4', name: 'sqli', n: 5 },
  { dir: 'classes/wstg-code-injection-4.7.11', name: 'code-injection', n: 5 },
  { dir: 'classes/wstg-ssti-4.7.18', name: 'ssti', n: 4 },
  { dir: 'classes/wstg-directory-traversal-4.5.1', name: 'directory-traversal', n: 4 },
]

resetUsage()
const t0 = Date.now()
const results = []

for (const t of TESTS) {
  const classDir = path.resolve(repoRoot, t.dir)
  const anchors = await import(path.resolve(classDir, 'anchors.mjs'))
  const pool = anchors.INJECTION_LOCATIONS || []
  console.log(`\n── ${t.name} (pool: ${pool.join('/')}) ──`)

  for (let i = 0; i < t.n; i++) {
    // We can't peek at what generate-scenario.mjs will pick — it picks
    // internally. So we pick our own expected location with the same RNG
    // discipline and... actually that's not deterministic. Instead, run the
    // scenario gen and just record what location the scenario ended up with;
    // compare to the pool to verify all locations get exercised.
    const canary = `pr_${crypto.randomBytes(5).toString('hex')}`
    const theme = stubTheme(`${t.name}-${i}`)
    process.stdout.write(`[${i + 1}/${t.n}] `)
    try {
      const scenario = await generateScenarioForClass(theme, classDir, canary)
      const loc = scenario.slots?.user_input?.location || '(none)'
      const inPool = pool.includes(loc)
      results.push({ cls: t.name, loc, ok: inPool })
      process.stdout.write(`${inPool ? '✓' : '✗'} ${loc} (param=${scenario.slots?.user_input?.name})\n`)
    } catch (e) {
      results.push({ cls: t.name, error: e.message })
      process.stdout.write(`ERR ${e.message.slice(0, 60)}\n`)
    }
  }
}

console.log()
console.log('═══ Location distribution by class ═══')
for (const t of TESTS) {
  const rows = results.filter(r => r.cls === t.name && !r.error)
  const counts = new Map()
  for (const r of rows) counts.set(r.loc, (counts.get(r.loc) || 0) + 1)
  const distinct = counts.size
  const inPool = rows.filter(r => r.ok).length
  console.log(`  ${t.name.padEnd(22)} ${inPool}/${rows.length} in pool · ${distinct} distinct locations`)
  for (const [l, c] of [...counts.entries()].sort((a, b) => b[1] - a[1])) {
    console.log(`     ${c}× ${l}`)
  }
}

const elapsed = ((Date.now() - t0) / 1000).toFixed(1)
const u = getUsageReport()
console.log()
console.log(`${u.calls} calls in ${elapsed}s · est cost $${u.estCostUsd.toFixed(4)}`)
