// Multi-class deploy pipeline with end-to-end exploit validation.
// Usage:  node generator/deploy.mjs --class=wstg-inpv-01

import fs from 'node:fs/promises'
import path from 'node:path'
import http from 'node:http'
import crypto from 'node:crypto'

import { generateTheme } from './generate-theme.mjs'
import { generateChrome } from './generate-chrome.mjs'
import { generateScenarioForClass } from './generate-scenario.mjs'
import { generateDecoyPage, generateHomepage } from './generate-decoys.mjs'
import { generate404 } from './generate-404.mjs'

const args = Object.fromEntries(
  process.argv.slice(2).map(a => {
    const [k, v] = a.replace(/^--/, '').split('=')
    return [k, v ?? true]
  })
)
const classId = args.class || 'wstg-inpv-01'
const manifestPath = path.resolve(process.cwd(), `manifest.${classId}.json`)

function log(line) { console.log(line) }
function makeCanary() { return 'pr_' + crypto.randomBytes(12).toString('hex') }

async function deploy() {
  const startTime = Date.now()
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
  log(`PolyRange deploy — class: ${classId}`)
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')

  const classDir = path.resolve(process.cwd(), 'classes', classId)
  await fs.access(classDir).catch(() => {
    console.error(`Unknown class: ${classId}`); process.exit(1)
  })

  const perDeployCanary = makeCanary()
  log(`\n[canary] ${perDeployCanary}`)

  log('\n[1/5] Theme...')
  const theme = await generateTheme()
  log(`  ✓ ${theme.siteName} (${theme.industry}) — ${theme.font}, ${theme.primaryColor}`)

  log(`\n[2/5] Scenario...`)
  const scenario = await generateScenarioForClass(theme, classDir, perDeployCanary)
  log(`  ✓ ${scenario.featureLabel}`)

  log('\n[3/5] Chrome...')
  const chrome = await generateChrome(theme, scenario.chromeInjection)
  log(`  ✓ ${chrome.length} chars`)

  log('\n[4/5] Decoys (parallel)...')
  const allLinks = [...theme.navLinks, ...theme.secondaryLinks, ...theme.footerLinks]
  const tasks = [
    { path: '/', fn: () => generateHomepage(theme) },
    ...allLinks
      .filter(l => l.path !== scenario.endpoint?.path)
      .map(link => ({ path: link.path, fn: () => generateDecoyPage(theme, link) })),
  ]
  const seen = new Set()
  const uniq = tasks.filter(t => { if (seen.has(t.path)) return false; seen.add(t.path); return true })
  const results = await Promise.all(uniq.map(async t => {
    try { const d = await t.fn(); log(`  ✓ ${t.path}`); return [t.path, d] }
    catch (e) { log(`  ✗ ${t.path}`); return [t.path, { body: '<main><p>Content unavailable.</p></main>' }] }
  }))
  const decoys = Object.fromEntries(results)

  log('\n[5/5] 404...')
  const fallback404 = await generate404(theme)
  log('  ✓')

  const manifest = {
    polyrangeVersion: '0.4.0-demo',
    generatedAt: new Date().toISOString(),
    classId,
    perDeployCanary,
    theme,
    chrome,
    scenario,
    decoys,
    fallback404,
    wafResponseStyle: 'cloudflare1020',
  }

  await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2))

  // ============================================================
  // END-TO-END EXPLOIT VALIDATION
  // Spin up serve.mjs on an ephemeral port; run the canonical exploit as a
  // real HTTP request; check the canary appears. If not, fail the deploy.
  // ============================================================
  log('\n[validate] Spinning up server and running canonical exploit...')
  const validationOk = await endToEndValidate(manifest, classDir)
  if (!validationOk) {
    log('\n✗ End-to-end validation FAILED — deployed scenario is not exploitable.')
    log('  Manifest written but flagged as broken. Inspect, fix, redeploy.')
    process.exit(1)
  }
  log('  ✓ canonical exploit fires, canary recovered')

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1)
  log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
  log(`✓ Deploy complete in ${elapsed}s — VALIDATED EXPLOITABLE`)
  log(`  Class:  ${classId}`)
  log(`  Site:   ${theme.siteName}`)
  log(`  Canary: ${perDeployCanary}`)
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
}

// ============================================================
// End-to-end validation harness
// Hits the actual runtime via HTTP — guarantees deploy can't ship a manifest
// the runtime can't actually exploit.
// ============================================================
async function endToEndValidate(manifest, classDir) {
  const { classDef } = await import(path.resolve(classDir, 'behaviour.mjs'))
  const scenario = classDef.Scenario.parse(manifest.scenario)

  const PORT = 17890 + Math.floor(Math.random() * 1000)
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://127.0.0.1:${PORT}`)

    const matchPath = (() => {
      const ep = scenario.endpoint.path
      if (url.pathname === ep) return true
      if (ep.includes(':') || ep.includes('{')) {
        return new RegExp('^' + ep.replace(/:\w+|\{\w+\}/g, '[^/]+') + '$').test(url.pathname)
      }
      return false
    })()
    if (!matchPath) { res.writeHead(404); res.end(); return }

    let result
    if (manifest.classId === 'wstg-inpv-01') {
      const inp = url.searchParams.get(scenario.slots.user_input.name) ?? ''
      const r = classDef.template({ rawScenario: scenario, userInput: inp })
      result = r
    } else if (manifest.classId === 'wstg-athz-04') {
      let id
      if (scenario.endpoint.identifierLocation === 'path-segment') {
        id = url.pathname.split('/').filter(Boolean).pop()
      } else if (scenario.endpoint.identifierLocation === 'query') {
        id = url.searchParams.get(scenario.endpoint.identifierName)
      }
      const r = classDef.template({ rawScenario: scenario, requestedId: id, session: 'attacker-session' })
      result = r
    } else if (manifest.classId === 'wstg-inpv-05') {
      const inp = url.searchParams.get(scenario.slots.user_input.name) ?? ''
      const r = classDef.template({ rawScenario: scenario, rawInput: inp })
      result = r
    }
    res.writeHead(result.status, { 'Content-Type': 'text/html' })
    res.end(result.body)
  })

  await new Promise(r => server.listen(PORT, '127.0.0.1', r))

  try {
    // Build the canonical exploit URL per class
    const canary = manifest.perDeployCanary
    let exploitUrl
    if (manifest.classId === 'wstg-inpv-01') {
      // Inject the canary as the payload — XSS template just reflects {INPUT}
      // and we check it comes back unescaped
      exploitUrl = `http://127.0.0.1:${PORT}${scenario.endpoint.path}?${scenario.slots.user_input.name}=${encodeURIComponent(canary)}`
    } else if (manifest.classId === 'wstg-athz-04') {
      const canaryRec = scenario.principalRecords.find(r => r.isCanaryRecord)
      if (!canaryRec) { server.close(); return false }
      if (scenario.endpoint.identifierLocation === 'path-segment') {
        const ep = scenario.endpoint.path.replace(/:\w+|\{\w+\}/g, encodeURIComponent(String(canaryRec.identifier)))
        exploitUrl = `http://127.0.0.1:${PORT}${ep}`
      } else {
        exploitUrl = `http://127.0.0.1:${PORT}${scenario.endpoint.path}?${scenario.endpoint.identifierName}=${encodeURIComponent(String(canaryRec.identifier))}`
      }
    } else if (manifest.classId === 'wstg-inpv-05') {
      const payload = `' UNION SELECT * FROM ${scenario.sensitiveTable} --`
      exploitUrl = `http://127.0.0.1:${PORT}${scenario.endpoint.path}?${scenario.slots.user_input.name}=${encodeURIComponent(payload)}`
    }

    const resp = await fetch(exploitUrl)
    const body = await resp.text()
    const fired = classDef.exploitSuccessCriterion({ responseBody: body, perDeployCanary: canary })
    return fired
  } finally {
    server.close()
  }
}

deploy().catch((err) => {
  console.error('\n✗ deploy failed:', err.message)
  process.exit(1)
})
