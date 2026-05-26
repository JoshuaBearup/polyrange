#!/usr/bin/env node
// Bulk cleanup of polyrange-* Fly apps.
// Examples:
//   node scripts/cleanup-fly.mjs --dry-run
//   node scripts/cleanup-fly.mjs --older-than=24h
//   node scripts/cleanup-fly.mjs --class=wstg-xss-4.7.1
//   node scripts/cleanup-fly.mjs --all --yes

import { spawn } from 'node:child_process'

const FLYCTL = process.env.FLYCTL_BIN || `${process.env.HOME}/.fly/bin/flyctl`

const args = Object.fromEntries(
  process.argv.slice(2).map(a => {
    const [k, v] = a.replace(/^--/, '').split('=')
    return [k, v ?? true]
  })
)

const dryRun = args['dry-run'] === true
const yes = args.yes === true
const all = args.all === true
const classFilter = typeof args.class === 'string' ? args.class : null
const olderThan = typeof args['older-than'] === 'string' ? parseDuration(args['older-than']) : null

function run(cmd, argv, opts = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, argv, { stdio: opts.quiet ? 'pipe' : 'inherit', ...opts })
    let out = ''
    if (opts.quiet) {
      p.stdout?.on('data', d => out += d)
      p.stderr?.on('data', d => out += d)
    }
    p.on('exit', code => code === 0 ? resolve(out) : reject(new Error(`exit ${code}\n${out}`)))
  })
}

function parseDuration(s) {
  // "24h" → milliseconds
  const m = s.match(/^(\d+)([smhd])$/)
  if (!m) throw new Error(`invalid --older-than: ${s} (expected like 24h, 30m, 7d)`)
  const n = parseInt(m[1], 10)
  const unit = m[2]
  return n * { s: 1000, m: 60000, h: 3600000, d: 86400000 }[unit]
}

// "1h37m ago" / "3d ago" / "2m ago" → ms since now
function parseFlyAge(s) {
  if (!s) return 0
  let total = 0
  const rx = /(\d+)([dhms])/g
  let m
  while ((m = rx.exec(s)) !== null) {
    total += parseInt(m[1], 10) * { s: 1000, m: 60000, h: 3600000, d: 86400000 }[m[2]]
  }
  return total
}

async function listApps() {
  const out = await run(FLYCTL, ['apps', 'list', '--json'], { quiet: true }).catch(async () => {
    // Fall back to text output if --json isn't supported
    return await run(FLYCTL, ['apps', 'list'], { quiet: true })
  })
  // Try JSON parse first
  try {
    const apps = JSON.parse(out)
    return apps.map(a => ({ name: a.Name || a.name, org: a.Organization?.Slug || a.org, status: a.Status || a.status }))
  } catch {
    // Text parse: skip header rows, parse each line
    return out.split('\n')
      .filter(l => l.includes('polyrange-'))
      .map(l => {
        const parts = l.split('│').map(p => p.trim()).filter(Boolean)
        return { name: parts[0], org: parts[1], status: parts[2], age: parts[3] }
      })
  }
}

const apps = await listApps()
const polyrange = apps.filter(a => a.name?.startsWith('polyrange-'))

let candidates = polyrange
if (classFilter) {
  const slug = classFilter.replace(/[._]/g, '-')
  candidates = candidates.filter(a => a.name.includes(slug))
}
if (olderThan) {
  candidates = candidates.filter(a => parseFlyAge(a.age) >= olderThan)
}
if (!all && !classFilter && !olderThan) {
  console.error('Refusing to act on all polyrange apps without explicit --all (or --class= / --older-than= filter)')
  console.error(`Found ${polyrange.length} polyrange apps. Re-run with --dry-run to preview, or pick a filter.`)
  process.exit(1)
}

console.log(`Polyrange apps in account: ${polyrange.length}`)
console.log(`Targeted for cleanup:      ${candidates.length}`)
if (dryRun || !candidates.length) {
  for (const a of candidates) console.log(`  - ${a.name}  (${a.status || 'unknown'}, ${a.age || '?'})`)
  if (dryRun) console.log('\n(dry-run — no apps destroyed)')
  process.exit(0)
}

if (!yes) {
  console.log('\nApps that will be destroyed:')
  for (const a of candidates) console.log(`  - ${a.name}  (${a.status || 'unknown'}, ${a.age || '?'})`)
  console.log('\nPass --yes to actually destroy.')
  process.exit(0)
}

for (const a of candidates) {
  process.stdout.write(`destroying ${a.name}... `)
  try {
    await run(FLYCTL, ['apps', 'destroy', a.name, '--yes'], { quiet: true })
    console.log('✓')
  } catch (err) {
    console.log(`✗ ${err.message.split('\n')[0]}`)
  }
}
console.log(`\nDone — ${candidates.length} app(s) destroyed.`)
