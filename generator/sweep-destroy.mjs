// Multi-class sweep teardown.
//
// Reads a sweep-deploy manifest CSV and destroys each Fly app listed in it.
// Use after a sweep run when the deployments are no longer needed.
//
// Usage:
//   node generator/sweep-destroy.mjs --run-id=<run-id>
//   node generator/sweep-destroy.mjs --run-id=<run-id> --concurrency=5
//   node generator/sweep-destroy.mjs --manifest=runs/X/manifest.csv

import fs from 'node:fs/promises'
import path from 'node:path'
import os from 'node:os'
import { spawn } from 'node:child_process'

const args = Object.fromEntries(
  process.argv.slice(2).map(a => {
    const [k, v] = a.replace(/^--/, '').split('=')
    return [k, v ?? true]
  })
)

const flyctlBin = process.env.FLYCTL || path.join(os.homedir(), '.fly', 'bin', 'flyctl')
const concurrency = Math.max(1, parseInt(args.concurrency ?? '4', 10))
const repoRoot = process.cwd()

let manifestPath
if (args.manifest) {
  manifestPath = path.resolve(repoRoot, args.manifest)
} else if (args['run-id']) {
  manifestPath = path.join(repoRoot, 'runs', args['run-id'], 'manifest.csv')
} else {
  console.error('Either --run-id=X or --manifest=path/to/manifest.csv is required.')
  process.exit(1)
}

const csv = await fs.readFile(manifestPath, 'utf-8').catch((e) => {
  console.error(`Could not read manifest: ${e.message}`)
  process.exit(1)
})

const rows = parseCsv(csv)
const toDestroy = rows.filter(r => r.app_name && r.status === 'deployed')

console.log('━'.repeat(72))
console.log('PolyRange sweep destroy')
console.log('━'.repeat(72))
console.log()
console.log(`  Manifest:    ${path.relative(repoRoot, manifestPath)}`)
console.log(`  Apps:        ${toDestroy.length}`)
console.log(`  Concurrency: ${concurrency}`)
console.log()

if (toDestroy.length === 0) {
  console.log('Nothing to destroy.')
  process.exit(0)
}

const results = { destroyed: 0, failed: 0 }
const queue = [...toDestroy]
let inFlight = 0
let totalCompleted = 0

await new Promise((resolve) => {
  function next() {
    while (inFlight < concurrency && queue.length > 0) {
      const row = queue.shift()
      inFlight++
      destroyOne(row.app_name).then(({ ok, error }) => {
        inFlight--
        totalCompleted++
        const tag = ok ? '✓' : '✗'
        const detail = ok ? '' : ` ${error}`
        console.log(`  [${totalCompleted}/${toDestroy.length}] ${tag} ${row.app_name.padEnd(50)}${detail}`)
        if (ok) results.destroyed++
        else results.failed++
        if (queue.length === 0 && inFlight === 0) resolve()
        else next()
      })
    }
  }
  next()
})

console.log()
console.log('━'.repeat(72))
console.log(`Sweep destroy complete`)
console.log(`  ✓ destroyed: ${results.destroyed} / ${toDestroy.length}`)
console.log(`  ✗ failed:    ${results.failed} / ${toDestroy.length}`)
console.log('━'.repeat(72))

if (results.failed > 0) process.exitCode = 1


// ── helpers ────────────────────────────────────────────────────────────────

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

function destroyOne(appName) {
  return new Promise((resolve) => {
    let output = ''
    const child = spawn(flyctlBin, ['apps', 'destroy', appName, '--yes'])
    child.stdout.on('data', (d) => { output += d })
    child.stderr.on('data', (d) => { output += d })
    child.on('close', (code) => {
      if (code === 0) resolve({ ok: true })
      else {
        const errSnip = (output.split('\n').find(l => l.toLowerCase().includes('error')) || output.trim().split('\n').pop() || '').slice(0, 100)
        resolve({ ok: false, error: errSnip })
      }
    })
  })
}
