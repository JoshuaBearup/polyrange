// Live knowledge-graph TUI for a PolyRange attack run.
//
// Folds the live NDJSON record stream (live-emit.mjs) through the KG vocabulary
// (kg-vocab.mjs) and redraws a terminal map of the attack surface as the agent
// discovers it: endpoints probed, parameters tested, injectable points, tables
// and columns leaked, and the flag once confirmed. Dependency-free ANSI so it
// adds nothing to install.
//
// Usage:
//   node kg-tui.mjs --tail   runs/<id>/traces/<agent>.live.ndjson   # genuine live run
//   node kg-tui.mjs --replay trace.json [--delay 120]               # replay a finished trace
//   node kg-tui.mjs --replay trace.json --once                      # render final frame, exit
//
// The fold is identical to the post-hoc view, so the live map and the analysed
// trace can never disagree.

import fs from 'node:fs/promises'
import { emptyGraph, foldStep, graphStats } from './kg-vocab.mjs'
import { replayTrace, tailStream } from './live-emit.mjs'

const C = {
  reset: '\x1b[0m', dim: '\x1b[2m', bold: '\x1b[1m',
  endpoint: '\x1b[36m', param: '\x1b[33m', table: '\x1b[35m',
  column: '\x1b[34m', hypothesis: '\x1b[90m', flag: '\x1b[32m',
  hot: '\x1b[7m', red: '\x1b[31m', green: '\x1b[32m',
}
const GLYPH = { endpoint: '◉', param: '◇', table: '▤', column: '·', hypothesis: '?', flag: '⚑' }

function render(state) {
  const { g, header, lastTouched, recentEdges, closed, outcome } = state
  const stats = graphStats(g)
  const out = []
  out.push(`${C.bold}PolyRange — live attack graph${C.reset}`)
  out.push(`${C.dim}${header}${C.reset}`)
  out.push('')

  const injectable = new Set([...g.edges.values()].filter(e => e.rel === 'injectable').map(e => e.from))
  for (const type of ['endpoint', 'param', 'hypothesis', 'table', 'column', 'flag']) {
    const nodes = [...g.nodes.values()].filter(n => n.type === type)
    if (!nodes.length) continue
    out.push(`${C[type]}${GLYPH[type]} ${type}${C.reset} ${C.dim}(${nodes.length})${C.reset}`)
    for (const n of nodes.slice(0, 12)) {
      const hot = lastTouched.has(n.key) ? `${C.hot}` : ''
      const flags = []
      if (injectable.has(n.key)) flags.push(`${C.red}injectable${C.reset}`)
      if (n.meta?.confirmed) flags.push(`${C.green}CONFIRMED${C.reset}`)
      const tail = flags.length ? '  ' + flags.join(' ') : ''
      out.push(`  ${hot}${n.label}${C.reset}${C.dim} ×${n.hits}${C.reset}${tail}`)
    }
    if (nodes.length > 12) out.push(`  ${C.dim}… +${nodes.length - 12} more${C.reset}`)
  }

  out.push('')
  out.push(`${C.dim}recent inferences:${C.reset}`)
  for (const e of recentEdges.slice(-5)) {
    out.push(`  ${C.dim}${shortKey(e.from)} ${C.reset}${relColor(e.rel)}─${e.rel}→${C.reset}${C.dim} ${shortKey(e.to)}${C.reset}`)
  }

  out.push('')
  out.push(`${C.dim}nodes ${stats.nodes} · edges ${stats.edges} · ` +
    Object.entries(stats.byRel).map(([k, v]) => `${k}:${v}`).join(' ') + C.reset)
  if (closed) {
    const solved = outcome?.solved
    out.push(solved ? `${C.green}${C.bold}SOLVED${C.reset} ${C.dim}flag ${outcome.flag ?? ''} · ${outcome.total_requests ?? '?'} reqs${C.reset}`
      : `${C.red}run ended — not solved${C.reset}`)
  }
  return out.join('\n')
}

const relColor = r => (r === 'injectable' || r === 'leaks') ? C.red : r === 'confirmed-by' ? C.green : C.dim
const shortKey = k => String(k).replace(/^(endpoint|param|table|column|hypothesis|flag|step|agent):/, m => m[0].toUpperCase() + ':').slice(0, 40)

function makeState() {
  return { g: emptyGraph(), header: '', lastTouched: new Set(), recentEdges: [], closed: false, outcome: null }
}

function applyRecord(state, rec) {
  if (rec.kind === 'open') {
    const a = rec.agent || {}, c = rec.cell || {}
    const served = a.model_served ?? 'unknown'
    const mismatch = a.model_served && a.model_requested && a.model_served !== a.model_requested ? ` ${C.red}(requested ${a.model_requested})${C.reset}` : ''
    state.header = `${c.class_id ?? '?'} tier ${c.tier ?? '?'} · ${a.harness ?? '?'} served ${served}${mismatch} · cell ${c.cell_id ?? '?'}`
  } else if (rec.kind === 'step') {
    const before = state.g.edges.size
    const touched = foldStep(state.g, rec.step)
    state.lastTouched = new Set(touched)
    const newEdges = [...state.g.edges.values()].slice(before)
    state.recentEdges.push(...newEdges)
  } else if (rec.kind === 'close') {
    state.closed = true; state.outcome = rec.outcome
  }
}

function draw(state) {
  process.stdout.write('\x1b[2J\x1b[H' + render(state) + '\n')
}

async function main() {
  const args = process.argv.slice(2)
  const has = f => args.includes(f)
  const val = (f, d) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : d }
  const replayPath = val('--replay')
  const tailPath = val('--tail')
  const delay = Number(val('--delay', '100'))
  const once = has('--once')
  const state = makeState()

  if (replayPath) {
    const trace = JSON.parse(await fs.readFile(replayPath, 'utf-8'))
    const records = [...replayTrace(trace)]
    if (once) { for (const r of records) applyRecord(state, r); draw(state); return }
    for (const r of records) {
      applyRecord(state, r); draw(state)
      if (r.kind === 'step') await new Promise(res => setTimeout(res, delay))
    }
    return
  }

  if (tailPath) {
    draw(state)
    const stop = tailStream(tailPath, rec => { applyRecord(state, rec); draw(state) })
    process.on('SIGINT', () => { stop(); process.stdout.write('\n'); process.exit(0) })
    await new Promise(() => {}) // run until Ctrl-C
  }

  console.error('usage: node kg-tui.mjs --tail <live.ndjson> | --replay <trace.json> [--delay ms] [--once]')
  process.exit(2)
}

main()
