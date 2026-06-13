// Live-emit transport for PolyRange attack traces.
//
// The post-hoc adapters reconstruct a whole trace from a harness log after the
// run. The live path emits the SAME step objects incrementally, as they happen,
// so a TUI (or any consumer) can build the knowledge graph in real time instead
// of waiting for the run to finish. Capture method on such a trace is "live".
//
// Wire format: newline-delimited JSON (NDJSON), one record per line, append-only.
//   line 1     {"kind":"open","cell":{...},"agent":{...},"provenance":{...}}
//   lines 2..n {"kind":"step","step":{...}}        // one schema step each
//   last line  {"kind":"close","outcome":{...}}    // optional; stream may end abruptly
//
// A step record is exactly a `steps[]` item from the trace schema, so the live
// stream and a reconstructed trace share one definition. Reassembling the file
// back into a full trace is loadStream(); a harness that crashes mid-run still
// leaves a valid partial graph because every line stands alone.

import fs from 'node:fs'
import readline from 'node:readline'

// Writer. Adapters call .open() once, .step() per turn, .close() at the end.
// sink is any object with write(string); defaults to an append stream on a path.
export class LiveEmitter {
  constructor(sink) {
    if (typeof sink === 'string') { this._own = fs.createWriteStream(sink, { flags: 'a' }); this.sink = this._own }
    else this.sink = sink
    this._index = 0
  }
  _emit(rec) { this.sink.write(JSON.stringify(rec) + '\n') }
  open(cell, agent, provenance = {}) {
    this._emit({ kind: 'open', cell, agent, provenance: { capture_method: 'live', ...provenance } })
  }
  // Accepts a step with or without an index; assigns a monotonic one if absent.
  step(step) {
    const s = step.index == null ? { ...step, index: this._index } : step
    this._index = Math.max(this._index, s.index) + 1
    this._emit({ kind: 'step', step: s })
    return s
  }
  close(outcome = {}) {
    this._emit({ kind: 'close', outcome })
    if (this._own) this._own.end()
  }
}

// Turn a finished trace into the ordered live record stream. Lets the TUI replay
// a historical run (and gives a deterministic test fixture) with zero new data.
export function* replayTrace(trace) {
  yield { kind: 'open', cell: trace.cell, agent: trace.agent, provenance: { ...(trace.provenance || {}), capture_method: 'live', replayed_from: trace.provenance?.capture_method || 'transcript' } }
  for (const step of trace.steps || []) yield { kind: 'step', step }
  yield { kind: 'close', outcome: trace.outcome || {} }
}

// Read an NDJSON live file fully and reassemble a trace-shaped object.
export async function loadStream(path) {
  const records = []
  const rl = readline.createInterface({ input: fs.createReadStream(path), crlfDelay: Infinity })
  for await (const line of rl) { const t = line.trim(); if (t) records.push(JSON.parse(t)) }
  return recordsToTrace(records)
}

export function recordsToTrace(records) {
  let cell = null, agent = null, provenance = null, outcome = null
  const steps = []
  for (const r of records) {
    if (r.kind === 'open') { cell = r.cell; agent = r.agent; provenance = r.provenance }
    else if (r.kind === 'step') steps.push(r.step)
    else if (r.kind === 'close') outcome = r.outcome
  }
  return { schema_version: '1.0.0', cell, agent, steps, outcome, provenance }
}

// Tail a live NDJSON file, invoking onRecord(record) for each line as it lands —
// existing lines first, then new appends. Returns a stop() function. Used by the
// TUI for a genuinely live (not replayed) run.
export function tailStream(path, onRecord, { fromStart = true } = {}) {
  let offset = 0
  let buf = ''
  let closed = false
  const pump = () => {
    if (closed) return
    let stat
    try { stat = fs.statSync(path) } catch { return }
    if (stat.size < offset) { offset = 0; buf = '' } // truncation/rotation
    if (stat.size === offset) return
    const stream = fs.createReadStream(path, { start: offset, end: stat.size - 1 })
    stream.on('data', d => { buf += d.toString('utf8') })
    stream.on('end', () => {
      offset = stat.size
      let nl
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim()
        buf = buf.slice(nl + 1)
        if (line) { try { onRecord(JSON.parse(line)) } catch { /* skip partial/corrupt */ } }
      }
    })
  }
  if (fromStart) { try { fs.closeSync(fs.openSync(path, 'a')) } catch {} }
  pump()
  const watcher = fs.watchFile(path, { interval: 150 }, pump)
  return () => { closed = true; fs.unwatchFile(path, pump); void watcher }
}
