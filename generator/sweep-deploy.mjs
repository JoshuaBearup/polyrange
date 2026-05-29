// Multi-class sweep deployer.
//
// Walks the class catalogue (or a user-supplied subset), deploys each class at
// the requested tier in waves of bounded concurrency, captures each deploy's
// URL / canary / controlKey to a per-run CSV manifest, and reports a summary
// at the end. Deploys are NOT --ephemeral by default — they stay up so an
// external agent harness can be pointed at the URLs.
//
// Usage:
//   node generator/sweep-deploy.mjs --tier=0 --concurrency=3 [--run-id=X] [--classes=all|csv|file:path]
//   node generator/sweep-deploy.mjs --tier=1 --concurrency=3 --classes=wstg-sqli-4.7.5.4,wstg-idor-4.5.4

import fs from 'node:fs/promises'
import path from 'node:path'
import { spawn } from 'node:child_process'

const args = Object.fromEntries(
  process.argv.slice(2).map(a => {
    const [k, v] = a.replace(/^--/, '').split('=')
    return [k, v ?? true]
  })
)

const tier = parseInt(args.tier ?? '0', 10)
const concurrency = Math.max(1, parseInt(args.concurrency ?? '3', 10))
const runId = args['run-id'] || new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19) + '-t' + tier
const classesArg = args.classes || 'all'
const target = args.target || 'fly'

if (![0, 1].includes(tier)) {
  console.error(`tier must be 0 or 1 (got ${tier})`)
  process.exit(1)
}

const repoRoot = process.cwd()
const runDir = path.join(repoRoot, 'runs', runId)
const logsDir = path.join(runDir, 'deploys')
const csvPath = path.join(runDir, 'manifest.csv')

await fs.mkdir(logsDir, { recursive: true })

const classList = await resolveClassList(classesArg)

if (classList.length === 0) {
  console.error('No classes resolved')
  process.exit(1)
}

console.log('━'.repeat(72))
console.log('PolyRange sweep deploy')
console.log('━'.repeat(72))
console.log()
console.log(`  Run ID:        ${runId}`)
console.log(`  Tier:          T${tier}`)
console.log(`  Concurrency:   ${concurrency} deploys in flight`)
console.log(`  Class count:   ${classList.length}`)
console.log(`  Manifest:      ${path.relative(repoRoot, csvPath)}`)
console.log(`  Logs:          ${path.relative(repoRoot, logsDir)}/`)
console.log()

const csvHeader = 'class_id,tier,status,app_name,url,canary,control_key,cost_usd,duration_s,deployed_at,error\n'
await fs.writeFile(csvPath, csvHeader)

const results = { deployed: 0, failed: 0, totalCost: 0, startedAt: Date.now() }
const queue = [...classList]
let inFlight = 0
let totalCompleted = 0

await new Promise((resolve) => {
  function next() {
    while (inFlight < concurrency && queue.length > 0) {
      const classId = queue.shift()
      const slot = classList.length - queue.length - inFlight
      inFlight++
      console.log(`  [${slot}/${classList.length}] → ${classId} (T${tier}) deploying...`)
      deployOne(classId, tier).then(async (result) => {
        inFlight--
        totalCompleted++
        await appendRow(csvPath, result)
        const tag = result.status === 'deployed' ? '✓' : '✗'
        const detail = result.status === 'deployed'
          ? `${result.duration_s}s · $${(result.cost_usd ?? 0).toFixed(2)} · ${result.url}`
          : (result.error || 'unknown failure').slice(0, 100)
        console.log(`  [${totalCompleted}/${classList.length}] ${tag} ${classId.padEnd(40)} ${detail}`)
        if (result.status === 'deployed') {
          results.deployed++
          results.totalCost += result.cost_usd || 0
        } else {
          results.failed++
        }
        if (queue.length === 0 && inFlight === 0) resolve()
        else next()
      })
    }
  }
  next()
})

const wallSeconds = ((Date.now() - results.startedAt) / 1000).toFixed(1)

console.log()
console.log('━'.repeat(72))
console.log(`Sweep complete in ${wallSeconds}s`)
console.log(`  ✓ deployed:  ${results.deployed} / ${classList.length}`)
console.log(`  ✗ failed:    ${results.failed} / ${classList.length}`)
console.log(`  total cost:  $${results.totalCost.toFixed(2)}`)
console.log()
console.log(`Manifest CSV: ${path.relative(repoRoot, csvPath)}`)
console.log(`Per-deploy logs: ${path.relative(repoRoot, logsDir)}/`)
console.log()
console.log(`Next: point your model harness at the URLs in the manifest.`)
console.log(`Then: node generator/sweep-destroy.mjs --run-id=${runId}`)
console.log('━'.repeat(72))

if (results.failed > 0) process.exitCode = 1


// ── helpers ────────────────────────────────────────────────────────────────

async function resolveClassList(spec) {
  if (spec === 'all') {
    const all = await fs.readdir(path.join(repoRoot, 'classes'))
    return all.filter(n => n.startsWith('wstg-') && !n.startsWith('_')).sort()
  }
  if (spec.startsWith('file:')) {
    const filePath = spec.slice('file:'.length)
    const content = await fs.readFile(filePath, 'utf-8')
    return content.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'))
  }
  return spec.split(',').map(s => s.trim()).filter(Boolean)
}

async function deployOne(classId, tier) {
  const startedAt = Date.now()
  const deployedAt = new Date().toISOString()
  const logPath = path.join(logsDir, `${classId}.log`)
  const logFh = await fs.open(logPath, 'w')

  let output = ''
  const child = spawn('node', [
    'generator/deploy.mjs',
    `--class=${classId}`,
    `--target=${target}`,
    `--tier=${tier}`,
  ], { env: process.env, cwd: repoRoot })

  child.stdout.on('data', (d) => { output += d; logFh.write(d) })
  child.stderr.on('data', (d) => { output += d; logFh.write(d) })

  await new Promise((res) => child.on('close', res))
  await logFh.close()

  const duration_s = ((Date.now() - startedAt) / 1000).toFixed(1)
  const result = parseDeployOutput(output, classId, tier, duration_s, deployedAt)

  // The local manifest file holds the controlKey (the runtime unlinks its
  // OWN copy in the container at startup; the local copy persists). Read it
  // before deleting so the row can carry the key.
  try {
    const localManifestPath = path.join(repoRoot, `manifest.${classId}.t${tier}.json`)
    const m = JSON.parse(await fs.readFile(localManifestPath, 'utf-8'))
    if (m.controlKey) result.control_key = m.controlKey
    await fs.unlink(localManifestPath).catch(() => {})
  } catch {
    // OK — manifest may not exist if deploy failed early
  }
  return result
}

function parseDeployOutput(output, classId, tier, duration_s, deployedAt) {
  const validated = /✓ Deploy complete.*VALIDATED at T/.test(output)
  const row = {
    class_id: classId,
    tier,
    status: validated ? 'deployed' : 'failed',
    app_name: '',
    url: '',
    canary: '',
    control_key: '',
    cost_usd: 0,
    duration_s,
    deployed_at: deployedAt,
    error: '',
  }
  const appMatch = output.match(/\[fly apps create\] ([a-z0-9-]+)/)
  if (appMatch) row.app_name = appMatch[1]
  const urlMatch = output.match(/deployed at (https?:\/\/[^\s]+)/)
  if (urlMatch) row.url = urlMatch[1]
  const canaryMatch = output.match(/Canary:\s+(pr_[a-f0-9]+)/)
  if (canaryMatch) row.canary = canaryMatch[1]
  const costMatch = output.match(/Est\. cost: \$([\d.]+)/)
  if (costMatch) row.cost_usd = parseFloat(costMatch[1])
  if (!validated) {
    const errMatch = output.match(/✗ (?:deploy failed|Solvability validation FAILED|Discovery validation FAILED|Negative-control validation FAILED): (.+?)(?:\n|$)/)
    if (errMatch) row.error = errMatch[1].slice(0, 240)
    else {
      const generic = output.match(/✗ (.+?)(?:\n|$)/m)
      if (generic) row.error = generic[1].slice(0, 240)
    }
  }
  return row
}

async function appendRow(csvPath, row) {
  const csvVal = (v) => {
    const s = String(v ?? '')
    return /[,"\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  const cols = [
    row.class_id, row.tier, row.status, row.app_name, row.url, row.canary,
    row.control_key, row.cost_usd, row.duration_s, row.deployed_at, row.error,
  ]
  await fs.appendFile(csvPath, cols.map(csvVal).join(',') + '\n')
}
