// Demonstrate how siteContext linkage changes the anchor output.
// For each theme, generate (a) a shared siteContext upstream and
// (b) the anchor with that context vs without. Show side-by-side.

import { loadDotEnv } from '../lib/precheck.mjs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
await loadDotEnv(repoRoot)

const { generateAnchor } = await import('../classes/wstg-backup-files-4.2.4/anchors.mjs')
const { callLLM, resetUsage, getUsageReport } = await import('../generator/call-llm.mjs')

// ─── New upstream step: generate shared siteContext from the theme ────────
const SITECTX_SYSTEM = `You produce shared site-context records for a per-deploy
security benchmark. Given a generic industry description, invent ONE specific
company that would plausibly operate in that industry, and return its name,
URL slug, and a short brand fragment usable in filenames.

Output ONLY valid JSON with this exact shape (no preamble, no code fences):
{
  "companyName": "Full company display name",
  "companySlug": "lowercase-hyphen-slug-for-urls-and-filenames",
  "shortBrand":  "very-short-one-word-fragment-for-tight-filenames"
}

Vary your invented companies across calls — do not converge on the same name
for a given industry.`

async function generateSiteContext({ theme }) {
  const text = await callLLM({
    system: SITECTX_SYSTEM,
    user: `Industry: ${theme.industry}\n\nProduce the JSON.`,
    maxTokens: 200,
    expectJson: true,
  })
  return text
}

// ─── New anchor variant that incorporates siteContext ──────────────────────
// We don't modify anchors.mjs for the demo — just call generateAnchor with
// theme having .industry overwritten to include the company name, and add
// a follow-up call that explicitly uses the slug. For clarity here I'll
// run TWO anchor calls per theme:
//   (A) current behaviour: theme.industry only
//   (B) new behaviour: theme.industry plus companyName / companySlug

// Hack-in for (B): patch theme to include explicit company info, and let
// the strategy hint use it.
async function generateAnchorWithContext({ theme, ctx }) {
  // Trick the existing generateAnchor by passing a richer theme.industry.
  // In the real wiring we'd add a siteContext parameter to generateAnchor.
  const patchedTheme = {
    industry: `${ctx.companyName} — ${theme.industry}. ` +
      `Company URL slug "${ctx.companySlug}", short brand "${ctx.shortBrand}". ` +
      `Where the filename strategy calls for a theme fragment or where the category ` +
      `asks for a service/site/account name, use "${ctx.companySlug}" or "${ctx.shortBrand}".`,
  }
  return generateAnchor({ callLLM, theme: patchedTheme })
}

const THEMES = [
  { industry: 'a regional e-commerce platform selling outdoor gear' },
  { industry: 'a small-business payroll service' },
  { industry: 'a healthcare appointment booking app' },
  { industry: 'an independent magazine subscription service' },
  { industry: 'a SaaS project-management tool' },
]

resetUsage()
const t0 = Date.now()

console.log('═══ siteContext linkage demonstration ' + '═'.repeat(55))
console.log()

for (const theme of THEMES) {
  console.log('─'.repeat(95))
  console.log('theme:', theme.industry)

  // Step 0: generate siteContext (shared upstream)
  const ctx = await generateSiteContext({ theme })
  console.log('siteContext:', JSON.stringify(ctx))
  console.log()

  // (A) Current: anchor with theme string only
  const currentRun = await generateAnchor({ callLLM, theme })
  console.log('  WITHOUT siteContext:')
  console.log('    seeded-dir: ' + currentRun.directory)
  console.log('    strategy:   ' + currentRun.strategy.slice(0, 80))
  console.log('    full path:  ' + (currentRun.anchor.match(/`([^`]+)`/)?.[1] || '(unparsed)'))
  console.log()

  // (B) New: anchor with siteContext injected
  const newRun = await generateAnchorWithContext({ theme, ctx })
  console.log('  WITH siteContext (slug="' + ctx.companySlug + '"):')
  console.log('    seeded-dir: ' + newRun.directory)
  console.log('    strategy:   ' + newRun.strategy.slice(0, 80))
  console.log('    full path:  ' + (newRun.anchor.match(/`([^`]+)`/)?.[1] || '(unparsed)'))
  console.log()
}

const elapsed = ((Date.now() - t0) / 1000).toFixed(1)
const u = getUsageReport()
console.log('─'.repeat(95))
console.log(`Generated in ${elapsed}s · ${u.calls} calls · est cost $${u.estCostUsd.toFixed(4)}`)
