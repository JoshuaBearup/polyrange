// Roll the (sync) pickAnchor() 100 times for admin-interfaces and
// platform-config, show table of picks + distribution.

import { ADMIN_POOL, pickAnchor as pickAdmin } from '../classes/wstg-admin-interfaces-4.2.5/anchors.mjs'
import { ARTIFACT_POOL, pickAnchor as pickArtifact } from '../classes/wstg-platform-config-4.2.2/anchors.mjs'

// Extract the FIRST path-looking token from an entry — these pools embed
// paths in prose ("a reachable /admin dashboard..." → "/admin")
function extractPath(s) {
  const m = s.match(/\/[A-Za-z0-9_./-]+/)
  return m ? m[0] : '(no path)'
}

function rollOnce(picker, pool) {
  const text = picker()
  // The pickAnchor wraps the pool entry with prose, but the entry itself is
  // somewhere in the returned text. Find which pool entry was picked by
  // matching the longest entry that appears as a substring.
  let entryIdx = -1
  for (let i = 0; i < pool.length; i++) {
    if (text.includes(pool[i])) { entryIdx = i; break }
  }
  const entry = entryIdx >= 0 ? pool[entryIdx] : '(unknown)'
  return { entryIdx, entry, path: extractPath(entry) }
}

function run(name, picker, pool, n = 100) {
  console.log('═'.repeat(95))
  console.log(`${name} — pool size ${pool.length}`)
  console.log('═'.repeat(95))
  console.log()

  const rolls = []
  for (let i = 0; i < n; i++) rolls.push(rollOnce(picker, pool))

  // Distribution
  const counts = new Map()
  for (const r of rolls) counts.set(r.entry, (counts.get(r.entry) || 0) + 1)
  const distinct = counts.size

  console.log(`Distinct pool entries drawn: ${distinct} / ${pool.length}`)
  console.log(`Most-drawn entry: ${Math.max(...counts.values())}×`)
  console.log(`Least-drawn (drawn at least once): ${Math.min(...counts.values())}×`)
  console.log(`Pool entries never drawn in this run: ${pool.length - distinct}`)
  console.log()

  // Table of all 100 rolls — # / path / entry
  const padR = (s, n) => String(s).slice(0, n).padEnd(n)
  console.log(padR('#', 4) + padR('path', 26) + 'entry')
  console.log('─'.repeat(95))
  for (let i = 0; i < n; i++) {
    const r = rolls[i]
    console.log(padR(String(i + 1), 4) + padR(r.path, 26) + r.entry.slice(0, 75))
  }
  console.log()

  // Distribution table — top 12 by frequency
  console.log('─ Top entries by frequency ' + '─'.repeat(60))
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1])
  for (const [entry, n] of sorted.slice(0, 12)) {
    console.log(`  ${String(n).padStart(3)}× ${extractPath(entry).padEnd(25)} ${entry.slice(0, 65)}`)
  }
  console.log()
}

run('ADMIN_POOL', pickAdmin, ADMIN_POOL)
run('ARTIFACT_POOL', pickArtifact, ARTIFACT_POOL)
