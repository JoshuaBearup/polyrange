// Adapter: Claude Code session transcript (.jsonl) -> PolyRange Attack Trace.
//
// This is a per-harness adapter. The PolyRange-side contract is the schema +
// ingest; each harness writes a thin translator like this. Covers any agent
// driven by Claude Code (e.g. a Meridian-provisioned attacker), where the
// transcript records per-turn served model, thinking blocks, tool calls, and
// tool results.
//
// Usage:
//   node adapter-claude-code.mjs <transcript.jsonl> <cell.json> <agent.json> > trace.json
//   cell.json:  { "cell_id": "...", "class_id": "...", "tier": 0, "target_url": "...", "canary": "pr_..." }
//   agent.json: { "harness": "claude-code", "model_requested": "claude-fable-5", "run_id": "..." }

import fs from 'node:fs/promises'

const ADAPTER_VERSION = '1.0.0'
const SCHEMA_VERSION = '1.0.0'
const MAX_OBS_CHARS = 2000

function textOf(block) {
  if (typeof block?.text === 'string') return block.text
  if (typeof block?.thinking === 'string') return block.thinking
  return ''
}

function classifyAction(command) {
  // A curl invocation is an HTTP request against the target; extract method+url.
  const isCurl = /(^|\s|;|&&|\|)curl(\s|$)/.test(command)
  if (!isCurl) return { kind: 'shell', detail: { command } }
  const methodMatch = command.match(/-X\s+([A-Z]+)/)
  const method = methodMatch ? methodMatch[1] : (/--data|--data-urlencode|-d\s/.test(command) ? 'POST' : 'GET')
  const urlMatch = command.match(/https?:\/\/[^\s"']+/)
  return { kind: 'http_request', detail: { method, url: urlMatch ? urlMatch[0] : null, command } }
}

function truncate(s) {
  if (typeof s !== 'string') return { detail: s, truncated: false }
  if (s.length <= MAX_OBS_CHARS) return { detail: s, truncated: false }
  return { detail: s.slice(0, MAX_OBS_CHARS), truncated: true }
}

function tagsFor(command, obsText) {
  const tags = []
  if (/__pr\/submit/.test(command)) tags.push('submit')
  if (/UNION|SELECT|OR\s+'?1'?='?1|sqlmap|--|information_schema|sqlite_master/i.test(command)) tags.push('payload')
  if (typeof obsText === 'string') {
    if (/"correct"\s*:\s*true/.test(obsText)) tags.push('flag-confirmed')
    if (/error|denied|forbidden|not have the same number/i.test(obsText)) tags.push('error-signal')
  }
  return tags
}

export async function adaptClaudeCode(transcriptPath, cell, agent) {
  const raw = await fs.readFile(transcriptPath, 'utf-8')
  const lines = raw.split('\n').filter(Boolean).map(l => { try { return JSON.parse(l) } catch { return null } }).filter(Boolean)

  // Index tool_results by tool_use_id (they arrive in subsequent user turns).
  const resultById = new Map()
  for (const ev of lines) {
    if (ev.type !== 'user') continue
    for (const block of ev.message?.content ?? []) {
      if (block?.type === 'tool_result' && block.tool_use_id) {
        const c = block.content
        const text = Array.isArray(c) ? c.map(x => x?.text ?? '').join('') : (typeof c === 'string' ? c : JSON.stringify(c ?? ''))
        resultById.set(block.tool_use_id, { text, isError: !!block.is_error })
      }
    }
  }

  const steps = []
  const servedModels = new Set()
  let pendingThought = null
  let submittedFlag = null
  let flagConfirmed = false

  for (const ev of lines) {
    if (ev.type !== 'assistant') continue
    const served = ev.message?.model ?? null
    if (served) servedModels.add(served)
    for (const block of ev.message?.content ?? []) {
      if (block?.type === 'thinking') { pendingThought = textOf(block).trim() || pendingThought; continue }
      if (block?.type === 'text') { const t = textOf(block).trim(); if (t) pendingThought = t; continue }
      if (block?.type !== 'tool_use') continue

      const command = block.input?.command ?? block.input?.description ?? JSON.stringify(block.input ?? {})
      const { kind, detail } = block.name === 'Bash'
        ? classifyAction(command)
        : { kind: 'tool', detail: { tool: block.name, input: block.input } }

      const result = resultById.get(block.id)
      const obsText = result?.text ?? null
      if (obsText && /"correct"\s*:\s*true/.test(obsText)) flagConfirmed = true
      const flagMatch = command.match(/pr_[0-9a-f]{24}/)
      if (flagMatch && /__pr\/submit/.test(command)) submittedFlag = flagMatch[0]

      const obs = obsText == null ? null : (() => {
        const { detail: d, truncated } = truncate(obsText)
        return { summary: (obsText.split('\n')[0] || '').slice(0, 200), status: result.isError ? 'error' : null, detail: d, truncated }
      })()

      steps.push({
        index: steps.length,
        thought: pendingThought,
        action: { kind, summary: (block.input?.description || command.split('\n')[0] || kind).slice(0, 200), detail },
        observation: obs,
        served_model: served,
        tags: tagsFor(command, obsText),
      })
      pendingThought = null
    }
  }

  const servedList = [...servedModels]
  const trace = {
    schema_version: SCHEMA_VERSION,
    cell,
    agent: {
      ...agent,
      model_served: servedList.length === 1 ? servedList[0] : (servedList[0] ?? null),
    },
    steps,
    outcome: {
      solved: flagConfirmed,
      flag: submittedFlag,
      flag_correct: flagConfirmed ? true : (submittedFlag ? false : null),
      total_requests: steps.filter(s => s.action.kind === 'http_request').length || null,
      duration_ms: null,
      served_model_consistent: servedList.length === 0 ? null : servedList.length === 1,
    },
    provenance: {
      adapter: 'adapter-claude-code',
      adapter_version: ADAPTER_VERSION,
      capture_method: 'transcript',
      redacted: false,
      notes: servedList.length > 1 ? `served model varied across turns: ${servedList.join(', ')}` : undefined,
    },
  }
  return trace
}

// CLI
if (import.meta.url === `file://${process.argv[1]}`) {
  const [transcriptPath, cellPath, agentPath] = process.argv.slice(2)
  if (!transcriptPath || !cellPath || !agentPath) {
    console.error('usage: node adapter-claude-code.mjs <transcript.jsonl> <cell.json> <agent.json>')
    process.exit(2)
  }
  const cell = JSON.parse(await fs.readFile(cellPath, 'utf-8'))
  const agent = JSON.parse(await fs.readFile(agentPath, 'utf-8'))
  const trace = await adaptClaudeCode(transcriptPath, cell, agent)
  process.stdout.write(JSON.stringify(trace, null, 2) + '\n')
}
