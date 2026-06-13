// Deterministic test: fold a real attack trace through the KG vocabulary and
// assert the graph has the structure the run actually had. No model calls.

import fs from 'node:fs/promises'
import assert from 'node:assert/strict'
import { stepsToGraph, graphToJSON, graphStats } from './kg-vocab.mjs'
import { replayTrace, recordsToTrace } from './live-emit.mjs'

const path = process.argv[2] || '/tmp/trace-cc75.json'
const trace = JSON.parse(await fs.readFile(path, 'utf-8'))

// 1. fold the whole trace
const g = stepsToGraph(trace.steps)
const json = graphToJSON(g)
const stats = graphStats(g)

// 2. live replay must produce an identical graph (fold is order-stable and the
//    two paths share one definition).
const replayed = recordsToTrace([...replayTrace(trace)])
const gLive = stepsToGraph(replayed.steps)
assert.deepEqual(graphStats(gLive), stats, 'live-replay graph must equal post-hoc graph')

// 3. structural assertions grounded in what a solved SQLi run must contain
const types = stats.byType
assert.ok(types.endpoint >= 1, 'expected at least one endpoint node')
assert.ok(types.param >= 1, 'expected at least one parameter node')
assert.ok(stats.byRel.probed >= 1, 'expected probed edges')

if (trace.outcome?.solved) {
  assert.ok(types.flag >= 1, 'solved run must have a flag node')
  const flag = json.nodes.find(n => n.type === 'flag')
  assert.ok(flag?.confirmed, 'solved run must have a confirmed flag')
  assert.ok(stats.byRel['confirmed-by'] >= 1, 'solved run must have a confirmed-by edge')
}

console.log('PASS', path)
console.log(JSON.stringify(stats, null, 2))
console.log('\nnodes:')
for (const n of json.nodes) console.log(`  ${n.type.padEnd(10)} ${n.label}${n.confirmed ? '  [CONFIRMED]' : ''}`)
console.log('\nedges:')
for (const e of json.edges) console.log(`  ${e.from}  -${e.rel}->  ${e.to}  (×${e.count})`)
