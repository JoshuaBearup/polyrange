// Shared helpers for PolyRange attack-trace adapters. Keeping action
// classification, observation truncation, tagging, and trace assembly in one
// place so every harness adapter produces identical, comparable output.

export const SCHEMA_VERSION = '1.0.0'
const MAX_OBS_CHARS = 2000

// Classify a shell command into an action. A curl invocation is an HTTP request
// against the target; everything else is a generic shell action.
export function classifyAction(command) {
  const isCurl = /(^|\s|;|&&|\|)curl(\s|$)/.test(command)
  if (!isCurl) return { kind: 'shell', detail: { command } }
  const methodMatch = command.match(/-X\s+([A-Z]+)/)
  const method = methodMatch ? methodMatch[1] : (/--data|--data-urlencode|-d\s/.test(command) ? 'POST' : 'GET')
  const urlMatch = command.match(/https?:\/\/[^\s"']+/)
  return { kind: 'http_request', detail: { method, url: urlMatch ? urlMatch[0] : null, command } }
}

export function truncate(s) {
  if (typeof s !== 'string') return { detail: s ?? null, truncated: false }
  if (s.length <= MAX_OBS_CHARS) return { detail: s, truncated: false }
  return { detail: s.slice(0, MAX_OBS_CHARS), truncated: true }
}

export function tagsFor(command, obsText) {
  const tags = []
  if (/__pr\/submit/.test(command)) tags.push('submit')
  if (/UNION|SELECT|OR\s+'?1'?='?1|sqlmap|--|information_schema|sqlite_master/i.test(command)) tags.push('payload')
  if (typeof obsText === 'string') {
    if (/"correct"\s*:\s*true/.test(obsText)) tags.push('flag-confirmed')
    if (/error|denied|forbidden|not have the same number/i.test(obsText)) tags.push('error-signal')
  }
  return tags
}

export function makeObservation(obsText, { isError = false } = {}) {
  if (obsText == null) return null
  const { detail, truncated } = truncate(obsText)
  return {
    summary: (String(obsText).split('\n')[0] || '').slice(0, 200),
    status: isError ? 'error' : null,
    detail,
    truncated,
  }
}

// Assemble the final trace object from collected steps + served-model set.
export function assembleTrace({ cell, agent, steps, servedModels, submittedFlag, flagConfirmed, provenance }) {
  const servedList = [...servedModels]
  return {
    schema_version: SCHEMA_VERSION,
    cell,
    agent: {
      ...agent,
      model_served: agent.model_served ?? (servedList.length === 1 ? servedList[0] : (servedList[0] ?? null)),
    },
    steps,
    outcome: {
      solved: !!flagConfirmed,
      flag: submittedFlag ?? null,
      flag_correct: flagConfirmed ? true : (submittedFlag ? false : null),
      total_requests: steps.filter(s => s.action.kind === 'http_request').length || null,
      duration_ms: null,
      served_model_consistent: servedList.length === 0 ? null : servedList.length === 1,
    },
    provenance,
  }
}
