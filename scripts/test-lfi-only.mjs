// Just LFI, 10 rolls, to verify pageParam diversifies after the revert.
import { loadDotEnv } from '../lib/precheck.mjs'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
await loadDotEnv(repoRoot)

const { generateScenarioForClass } = await import('../generator/generate-scenario.mjs')
const { resetUsage, getUsageReport } = await import('../generator/call-llm.mjs')

// 10 distinct themes — varied industries, eras, voices, brand names.
// In production generate-theme.mjs draws from 4.6M-combination space;
// this stub gives a representative 10-theme slice so the LFI LLM has to
// pick a context-rooted param name per industry.
const THEMES = [
  { industryVertical: 'a regional e-commerce platform selling outdoor gear', era: '2020s modern startup', voice: 'utilitarian and no-nonsense', brandName: 'TrailVend' },
  { industryVertical: 'a small-business payroll service', era: '2010s consumer SaaS', voice: 'serious and professional', brandName: 'PayrollHub' },
  { industryVertical: 'a healthcare appointment booking app', era: '2020s modern startup', voice: 'corporate and institutional', brandName: 'MediBook' },
  { industryVertical: 'an independent magazine subscription service', era: '2010s consumer SaaS', voice: 'boutique and artisan', brandName: 'CuratedPages' },
  { industryVertical: 'a SaaS project-management tool', era: '2020s modern startup', voice: 'playful and approachable', brandName: 'TaskFlow' },
  { industryVertical: 'a municipal water-utility billing site', era: '2000s enterprise software', voice: 'corporate and institutional', brandName: 'AquaServ' },
  { industryVertical: 'a hotel reservation system', era: '2010s consumer SaaS', voice: 'serious and professional', brandName: 'StayQuick' },
  { industryVertical: 'a regional bank online portal', era: '1990s legacy enterprise', voice: 'corporate and institutional', brandName: 'Heartland' },
  { industryVertical: 'a university course registration portal', era: '2000s enterprise software', voice: 'utilitarian and no-nonsense', brandName: 'AcademiaCore' },
  { industryVertical: 'a legal document management service', era: '2010s consumer SaaS', voice: 'boutique and artisan', brandName: 'LexiVault' },
]

const stubTheme = (i) => ({
  ...THEMES[i],
  maturity: 'venture-backed startup',
  layoutArchetype: 'top horizontal nav bar, wide content area below',
  designLanguage: 'flat design',
  colorTreatment: 'light mode, muted and restrained',
  colorFamily: 'blue',
  productConcept: 'a sample app',
})

const classDir = path.resolve(repoRoot, 'classes/wstg-lfi-4.7.11.1')
resetUsage()
const t0 = Date.now()
const rows = []

for (let i = 0; i < 10; i++) {
  const canary = `pr_${crypto.randomBytes(5).toString('hex')}`
  const theme = stubTheme(i)
  const themeShort = theme.industryVertical.slice(0, 28)
  process.stdout.write(`[${i + 1}/10 ${themeShort}] `)
  try {
    const s = await generateScenarioForClass(theme, classDir, canary)
    rows.push({ theme: themeShort, param: s.pageParam, path: s.endpoint?.path })
    process.stdout.write(`${s.pageParam} · ${s.endpoint?.path}\n`)
  } catch (e) {
    rows.push({ theme: themeShort, error: e.message.slice(0, 80) })
    process.stdout.write(`ERR ${e.message.slice(0, 60)}\n`)
  }
}

const padR = (s, n) => String(s).slice(0, n).padEnd(n)
console.log()
console.log('═══ LFI — 10 deploys, varied themes ═══════════════════════════════════')
console.log(padR('#', 4) + padR('theme', 30) + padR('pageParam', 20) + 'endpoint path')
console.log('─'.repeat(95))
rows.forEach((r, i) => {
  if (r.error) { console.log(padR(String(i+1), 4) + padR(r.theme, 30) + 'ERROR: ' + r.error); return }
  console.log(padR(String(i+1), 4) + padR(r.theme, 30) + padR(r.param, 20) + r.path)
})

console.log()
const dist = new Map()
for (const r of rows) if (!r.error) dist.set(r.param, (dist.get(r.param) || 0) + 1)
console.log(`Distinct pageParam values: ${dist.size}/${rows.filter(r => !r.error).length}`)
for (const [p, c] of [...dist.entries()].sort((a,b) => b[1] - a[1])) {
  console.log(`  ${c}× ${p}`)
}

const u = getUsageReport()
console.log()
console.log(`${u.calls} calls in ${((Date.now() - t0) / 1000).toFixed(1)}s · est cost $${u.estCostUsd.toFixed(4)}`)
