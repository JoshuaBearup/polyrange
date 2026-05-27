// Static conformance sweep — no deploys, no LLM. Imports every class's modules
// and asserts the classDef interface + supporting files are intact. Catches
// structural drift from shared-infra changes (broken imports, missing methods,
// schema breakage) in seconds, for free. NOT a substitute for live validation
// (solvability/discovery/oracle need a running target) — a fast pre-check.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const SKIP = new Set(['wstg-search-recon-4.1.1']) // stale / out-of-scope
const REQUIRED_FN = ['matchesRequest', 'handleRequest', 'fireExploit', 'exploitSuccessCriterion']
const DISCOVERY = ['knowledge', 'fingerprint', 'observation', 'lead']

const classes = fs.readdirSync(path.join(ROOT, 'classes'))
  .filter(d => (d.startsWith('wstg-') || d.startsWith('apisec-')) && !SKIP.has(d)).sort()

const results = []
for (const cls of classes) {
  const dir = path.join(ROOT, 'classes', cls)
  const p = []
  let classDef

  try {
    const sc = await import(path.join(dir, 'scenario.mjs'))
    if (!sc.Scenario || typeof sc.Scenario.safeParse !== 'function') p.push('scenario.mjs: no valid Zod Scenario')
  } catch (e) { p.push('scenario.mjs import: ' + e.message.split('\n')[0]) }

  try {
    const b = await import(path.join(dir, 'behaviour.mjs'))
    classDef = b.classDef
    if (!classDef) p.push('behaviour.mjs: no classDef export')
    else {
      if (!classDef.wstgId) p.push('classDef.wstgId missing')
      if (!classDef.class) p.push('classDef.class missing')
      if (!classDef.Scenario) p.push('classDef.Scenario missing')
      for (const fn of REQUIRED_FN) if (typeof classDef[fn] !== 'function') p.push(`classDef.${fn} missing/not a fn`)
      if (classDef.backend && typeof classDef.backend.spec !== 'function') p.push('classDef.backend.spec not a fn')
      if (classDef.backend && !fs.existsSync(path.join(dir, 'backends'))) p.push('backend declared but no backends/ dir')
      if (classDef.discoveryMode && !DISCOVERY.includes(classDef.discoveryMode)) p.push('bad discoveryMode: ' + classDef.discoveryMode)
      for (const hook of ['discoveryStaticOk', 'discoveryTargetPath', 'canaryPlacementOk', 'proofTarget']) {
        if (hook in classDef && typeof classDef[hook] !== 'function') p.push(`classDef.${hook} present but not a fn`)
      }
    }
  } catch (e) { p.push('behaviour.mjs import: ' + e.message.split('\n')[0]) }

  const defPath = path.join(dir, 'defences.mjs')
  const declaresT1 = classDef?.defenceTiers?.some(t => t > 0)
  if (fs.existsSync(defPath)) {
    try {
      const d = await import(defPath)
      if (!d.defences || typeof d.defences !== 'object') p.push('defences.mjs: no defences object')
      else if (!d.defences[0]) p.push('defences.mjs: no tier-0 entry')
      if (declaresT1 && typeof d.generateT1Config !== 'function') p.push('declares T1+ but no generateT1Config')
    } catch (e) { p.push('defences.mjs import: ' + e.message.split('\n')[0]) }
  } else if (declaresT1) {
    p.push('declares T1+ tiers but no defences.mjs')
  }

  const anchPath = path.join(dir, 'anchors.mjs')
  if (fs.existsSync(anchPath)) {
    try {
      const a = await import(anchPath)
      if (typeof a.pickAnchor !== 'function') p.push('anchors.mjs: pickAnchor not a fn')
      else if (a.pickAnchor() == null) p.push('anchors.pickAnchor() returned null')
    } catch (e) { p.push('anchors.mjs import: ' + e.message.split('\n')[0]) }
  }

  if (!fs.existsSync(path.join(dir, 'infra', 'Dockerfile'))) p.push('infra/Dockerfile missing')
  if (!fs.existsSync(path.join(dir, 'infra', 'package.json'))) p.push('infra/package.json missing')

  results.push({ cls, ok: p.length === 0, problems: p })
}

let pass = 0
for (const r of results) {
  if (r.ok) { pass++; console.log(`PASS  ${r.cls}`) }
  else { console.log(`FAIL  ${r.cls}`); r.problems.forEach(x => console.log(`        - ${x}`)) }
}
console.log(`\n${pass}/${results.length} classes pass static conformance`)
process.exit(pass === results.length ? 0 : 1)
