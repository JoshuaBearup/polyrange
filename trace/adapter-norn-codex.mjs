// Adapter: norn / Codex rollout session (.jsonl) -> PolyRange Attack Trace.
//
// norn executes via Codex; each run writes a rollout log under
// ~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl whose lines are
// { payload, timestamp, type }. We map exec_command function calls to actions,
// their paired function_call_output to observations, and the model's visible
// agent_message narration to the per-step thought.
//
// NOTE on fidelity: Codex's `reasoning` payloads carry no summary text in the
// rollout (hidden reasoning is not exposed), so unlike the Claude Code adapter
// the `thought` field here is the model's *visible narration*, not its hidden
// chain of thought. capture_method records this so consumers weight it correctly.
//
// Usage:
//   node adapter-norn-codex.mjs <rollout.jsonl> <cell.json> <agent.json> > trace.json

import fs from 'node:fs/promises'
import { classifyAction, tagsFor, makeObservation, assembleTrace } from './trace-lib.mjs'

const ADAPTER_VERSION = '1.0.0'

export async function adaptNornCodex(rolloutPath, cell, agent) {
  const raw = await fs.readFile(rolloutPath, 'utf-8')
  const events = raw.split('\n').filter(Boolean)
    .map(l => { try { return JSON.parse(l) } catch { return null } })
    .filter(Boolean)
    .map(e => e.payload ?? e)

  // Pair outputs to calls by call_id.
  const outputById = new Map()
  for (const p of events) {
    if (p.type === 'function_call_output' && p.call_id) {
      const out = typeof p.output === 'string' ? p.output : (p.output?.content ?? JSON.stringify(p.output ?? ''))
      outputById.set(p.call_id, out)
    }
  }

  const steps = []
  const servedModels = new Set()
  let pendingThought = null
  let submittedFlag = null
  let flagConfirmed = false

  for (const p of events) {
    // The model's visible narration — best-available "thought" for Codex.
    if (p.type === 'agent_message') {
      const msg = (p.message ?? p.text ?? '').trim()
      if (msg) pendingThought = msg.slice(0, 1000)
      continue
    }
    if (p.type === 'turn_context' && p.model) servedModels.add(p.model)
    if (p.type !== 'function_call') continue

    let cmd = ''
    try { cmd = JSON.parse(p.arguments ?? '{}').cmd ?? '' } catch { cmd = p.arguments ?? '' }
    if (Array.isArray(cmd)) cmd = cmd.join(' ')
    if (!cmd) continue

    const { kind, detail } = classifyAction(cmd)
    const obsText = outputById.get(p.call_id) ?? null
    if (obsText && /"correct"\s*:\s*true/.test(obsText)) flagConfirmed = true
    const flagMatch = cmd.match(/pr_[0-9a-f]{24}/)
    if (flagMatch && /__pr\/submit/.test(cmd)) submittedFlag = flagMatch[0]
    const isError = typeof obsText === 'string' && /exited with code [1-9]/.test(obsText)

    steps.push({
      index: steps.length,
      thought: pendingThought,
      action: { kind, summary: cmd.split('\n')[0].slice(0, 200), detail },
      observation: makeObservation(obsText, { isError }),
      served_model: [...servedModels].slice(-1)[0] ?? null,
      tags: tagsFor(cmd, obsText),
    })
    pendingThought = null
  }

  return assembleTrace({
    cell,
    agent,
    steps,
    servedModels,
    submittedFlag,
    flagConfirmed,
    provenance: {
      adapter: 'adapter-norn-codex',
      adapter_version: ADAPTER_VERSION,
      capture_method: 'transcript',
      redacted: false,
      notes: 'thought = model visible narration (agent_message); Codex hidden reasoning is not exposed in the rollout.',
    },
  })
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [rolloutPath, cellPath, agentPath] = process.argv.slice(2)
  if (!rolloutPath || !cellPath || !agentPath) {
    console.error('usage: node adapter-norn-codex.mjs <rollout.jsonl> <cell.json> <agent.json>')
    process.exit(2)
  }
  const cell = JSON.parse(await fs.readFile(cellPath, 'utf-8'))
  const agent = JSON.parse(await fs.readFile(agentPath, 'utf-8'))
  const trace = await adaptNornCodex(rolloutPath, cell, agent)
  process.stdout.write(JSON.stringify(trace, null, 2) + '\n')
}
