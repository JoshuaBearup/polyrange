// Generate 10 sqli + 10 lfi scenarios and report the injection points
// (location, parameter name, endpoint path, initial value). No deploy.

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
  productConcept: 'a sample app',
})

resetUsage()
const t0 = Date.now()

async function rollClass(label, classRelDir, n) {
  const classDir = path.resolve(repoRoot, classRelDir)
  const rows = []
  for (let i = 0; i < n; i++) {
    const canary = `pr_${crypto.randomBytes(5).toString('hex')}`
    const theme = stubTheme(`${label}-${i}`)
    process.stdout.write(`[${label} ${i + 1}/${n}] `)
    try {
      const s = await generateScenarioForClass(theme, classDir, canary)
      const slot = s.slots?.user_input
      const row = {
        loc: slot?.location || (s.pageParam ? 'query (legacy schema)' : '(no slot)'),
        name: slot?.name || s.pageParam || '(none)',
        method: s.endpoint?.method || 'GET',
        path: s.endpoint?.path || '(none)',
        initialValue: slot?.initialValue || '(none)',
      }
      rows.push(row)
      process.stdout.write(`${row.loc} · ${row.name} · ${row.method} ${row.path}\n`)
    } catch (e) {
      rows.push({ error: e.message.slice(0, 80) })
      process.stdout.write(`ERR ${e.message.slice(0, 60)}\n`)
    }
  }
  return rows
}

console.log()
const sqliRows = await rollClass('sqli', 'classes/wstg-sqli-4.7.5.4', 10)
console.log()
const lfiRows = await rollClass('lfi', 'classes/wstg-lfi-4.7.11.1', 10)

const padR = (s, n) => String(s).slice(0, n).padEnd(n)

console.log()
console.log('═══ SQLi — 10 deploys ═══════════════════════════════════════════════════════════')
console.log(padR('#', 4) + padR('location', 15) + padR('param name', 30) + padR('method', 8) + padR('initial', 15) + 'endpoint path')
console.log('─'.repeat(115))
sqliRows.forEach((r, i) => {
  if (r.error) { console.log(padR(String(i+1), 4) + 'ERROR: ' + r.error); return }
  console.log(padR(String(i+1), 4) + padR(r.loc, 15) + padR(r.name, 30) + padR(r.method, 8) + padR(r.initialValue, 15) + r.path)
})

console.log()
console.log('═══ SQLi — distribution ═══')
const dist = new Map()
for (const r of sqliRows) if (!r.error) dist.set(r.loc, (dist.get(r.loc) || 0) + 1)
for (const [l, c] of [...dist.entries()].sort((a, b) => b[1] - a[1])) console.log(`  ${c}× ${l}`)

console.log()
console.log('═══ LFI — 10 deploys ═══════════════════════════════════════════════════════════')
console.log(padR('#', 4) + padR('location', 30) + padR('param name', 20) + padR('method', 8) + 'endpoint path')
console.log('─'.repeat(95))
lfiRows.forEach((r, i) => {
  if (r.error) { console.log(padR(String(i+1), 4) + 'ERROR: ' + r.error); return }
  console.log(padR(String(i+1), 4) + padR(r.loc, 30) + padR(r.name, 20) + padR(r.method, 8) + r.path)
})

const elapsed = ((Date.now() - t0) / 1000).toFixed(1)
const u = getUsageReport()
console.log()
console.log(`Total: ${u.calls} calls in ${elapsed}s · est cost $${u.estCostUsd.toFixed(4)}`)
