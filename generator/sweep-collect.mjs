// Multi-deploy signature collector.
//
// Walks a sweep-deploy manifest CSV, queries /__pr/signature on each
// deployment with the per-deploy control key, and writes a per-model
// results CSV. Run this AFTER your agent has finished attacking the
// deployments — the signatures carry solved / time / requests / payload
// captured by the runtime during the agent's session.
//
// Usage:
//   node generator/sweep-collect.mjs --run-id=<id> --model=<model-name>
//   node generator/sweep-collect.mjs --manifest=runs/X/manifest.csv \
//     --model=opus-4-8 --output=runs/X/opus.csv

import fs from 'node:fs/promises'
import path from 'node:path'

const args = Object.fromEntries(
  process.argv.slice(2).map(a => {
    const [k, v] = a.replace(/^--/, '').split('=')
    return [k, v ?? true]
  })
)

const repoRoot = process.cwd()
const model = args.model
if (!model) {
  console.error('--model=<model-name> is required (used as a column value + in the output filename)')
  process.exit(1)
}

let manifestPath
if (args.manifest) {
  manifestPath = path.resolve(repoRoot, args.manifest)
} else if (args['run-id']) {
  manifestPath = path.join(repoRoot, 'runs', args['run-id'], 'manifest.csv')
} else {
  console.error('Either --run-id=X or --manifest=path/to/manifest.csv is required')
  process.exit(1)
}

const concurrency = Math.max(1, parseInt(args.concurrency ?? '5', 10))
const outputPath = args.output || (args['run-id']
  ? path.join(repoRoot, 'runs', args['run-id'], `results-${sanitiseFileSlug(model)}.csv`)
  : path.join(repoRoot, `results-${sanitiseFileSlug(model)}.csv`))

const csv = await fs.readFile(manifestPath, 'utf-8').catch((e) => {
  console.error(`Could not read manifest: ${e.message}`)
  process.exit(1)
})

const rows = parseCsv(csv)
const toCollect = rows.filter(r => r.url && r.control_key && r.status === 'deployed')

console.log('━'.repeat(72))
console.log('PolyRange signature collector')
console.log('━'.repeat(72))
console.log()
console.log(`  Manifest:   ${path.relative(repoRoot, manifestPath)}`)
console.log(`  Model:      ${model}`)
console.log(`  Output:     ${path.relative(repoRoot, outputPath)}`)
console.log(`  Deploys:    ${toCollect.length}`)
console.log(`  Concurrency: ${concurrency}`)
console.log()

if (toCollect.length === 0) {
  console.log('Nothing to collect.')
  process.exit(0)
}

const resultsHeader = 'class_id,tier,model,url,canary,solved,time_to_solve_ms,requests_to_solve,total_requests,started_at,solve_method,solve_path,solve_query,collected_at,error\n'
await fs.mkdir(path.dirname(outputPath), { recursive: true })
await fs.writeFile(outputPath, resultsHeader)

const queue = [...toCollect]
let inFlight = 0
let totalCompleted = 0
const summary = { solved: 0, unsolved: 0, errored: 0 }

await new Promise((resolve) => {
  function next() {
    while (inFlight < concurrency && queue.length > 0) {
      const row = queue.shift()
      inFlight++
      collectOne(row).then(async (result) => {
        inFlight--
        totalCompleted++
        await appendRow(outputPath, result)
        const tag = result.error ? '✗' : (result.solved === 'true' ? '✓' : '·')
        const detail = result.error
          ? `error: ${result.error}`
          : (result.solved === 'true'
              ? `solved in ${formatMs(result.time_to_solve_ms)} / ${result.requests_to_solve} reqs`
              : `not solved (${result.total_requests} reqs)`)
        console.log(`  [${totalCompleted}/${toCollect.length}] ${tag} ${row.class_id.padEnd(40)} ${detail}`)
        if (result.error) summary.errored++
        else if (result.solved === 'true') summary.solved++
        else summary.unsolved++
        if (queue.length === 0 && inFlight === 0) resolve()
        else next()
      })
    }
  }
  next()
})

const total = summary.solved + summary.unsolved + summary.errored
const solveRate = (summary.solved + summary.unsolved) > 0
  ? (summary.solved / (summary.solved + summary.unsolved)).toFixed(3)
  : 'n/a'

console.log()
console.log('━'.repeat(72))
console.log(`Collection complete`)
console.log(`  ✓ solved:   ${summary.solved} / ${total}`)
console.log(`  · unsolved: ${summary.unsolved} / ${total}`)
console.log(`  ✗ errored:  ${summary.errored} / ${total}`)
console.log(`  solve rate: ${solveRate} (excluding errors)`)
console.log()
console.log(`Results CSV: ${path.relative(repoRoot, outputPath)}`)
console.log()
console.log(`Next: collect for the other model, then run`)
console.log(`  node generator/render-report.mjs --runs=<csv1>,<csv2>`)
console.log('━'.repeat(72))


// ── helpers ────────────────────────────────────────────────────────────────

async function collectOne(row) {
  const collectedAt = new Date().toISOString()
  const result = {
    class_id: row.class_id,
    tier: row.tier,
    model,
    url: row.url,
    canary: row.canary,
    solved: '',
    time_to_solve_ms: '',
    requests_to_solve: '',
    total_requests: '',
    started_at: '',
    solve_method: '',
    solve_path: '',
    solve_query: '',
    collected_at: collectedAt,
    error: '',
  }
  try {
    const sigUrl = `${row.url.replace(/\/$/, '')}/__pr/signature`
    const r = await fetch(sigUrl, {
      headers: { 'x-pr-control': row.control_key },
    })
    if (!r.ok) {
      result.error = `HTTP ${r.status}`
      return result
    }
    const sig = await r.json()
    result.solved = String(sig.solved ?? false)
    result.time_to_solve_ms = sig.timeToSolveMs ?? ''
    result.requests_to_solve = sig.requestsToSolve ?? ''
    result.total_requests = sig.requests ?? ''
    result.started_at = sig.startedAt ? new Date(sig.startedAt).toISOString() : ''
    if (sig.solvePayload) {
      result.solve_method = sig.solvePayload.method || ''
      result.solve_path = sig.solvePayload.path || ''
      result.solve_query = sig.solvePayload.query || ''
    }
  } catch (e) {
    result.error = (e.message || String(e)).slice(0, 200)
  }
  return result
}

function parseCsv(text) {
  const lines = text.split(/\r?\n/).filter(Boolean)
  if (lines.length === 0) return []
  const headers = splitCsvLine(lines[0])
  return lines.slice(1).map(line => {
    const cols = splitCsvLine(line)
    const row = {}
    headers.forEach((h, i) => { row[h] = cols[i] ?? '' })
    return row
  })
}

function splitCsvLine(line) {
  const out = []
  let cur = ''
  let inQ = false
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (inQ) {
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i++ }
      else if (c === '"') inQ = false
      else cur += c
    } else {
      if (c === ',') { out.push(cur); cur = '' }
      else if (c === '"') inQ = true
      else cur += c
    }
  }
  out.push(cur)
  return out
}

function csvVal(v) {
  const s = String(v ?? '')
  return /[,"\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

async function appendRow(csvPath, row) {
  const cols = [
    row.class_id, row.tier, row.model, row.url, row.canary, row.solved,
    row.time_to_solve_ms, row.requests_to_solve, row.total_requests, row.started_at,
    row.solve_method, row.solve_path, row.solve_query, row.collected_at, row.error,
  ]
  await fs.appendFile(csvPath, cols.map(csvVal).join(',') + '\n')
}

function formatMs(ms) {
  const n = parseInt(ms, 10)
  if (!n || Number.isNaN(n)) return '?'
  if (n < 1000) return `${n}ms`
  if (n < 60000) return `${(n / 1000).toFixed(1)}s`
  const min = Math.floor(n / 60000)
  const sec = Math.floor((n % 60000) / 1000)
  return `${min}m${sec.toString().padStart(2, '0')}s`
}

function sanitiseFileSlug(s) {
  return String(s).replace(/[^a-zA-Z0-9._-]/g, '-').slice(0, 60)
}
