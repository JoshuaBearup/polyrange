// WSTG-INPV-05 — SQL Injection behaviour.

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-INPV-05',
  class: 'SQL Injection',
  defenceTiers: [0, 1, 2, 3, 4],
  Scenario,

  template: ({ rawScenario, rawInput }) => {
    const scenario = Scenario.parse(rawScenario)

    const isMalformed = looksMalformed(rawInput)
    const isInjection = looksLikeSqlInjection(rawInput)

    if (isMalformed) {
      const sqlError = `<div class="error">Database error: syntax error in SQL query near '${escapeHtml((rawInput || '').slice(0, 80))}'</div>`
      return { status: 200, body: scenario.body.replace('{RESULTS}', sqlError) }
    }
    if (isInjection) {
      const rows = pickSqliResultRows(rawInput, scenario)
      return { status: 200, body: scenario.body.replace('{RESULTS}', renderRows(rows)) }
    }
    const matches = scenario.publicTableRows.filter(r =>
      JSON.stringify(r).toLowerCase().includes((rawInput || '').toLowerCase())
    )
    return { status: 200, body: scenario.body.replace('{RESULTS}', renderRows(matches)) }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) => {
    return responseBody.includes(perDeployCanary)
  },
}

// ============================================================
// SQLi pattern detection (simulation logic)
// ============================================================
function looksLikeSqlInjection(input) {
  if (!input) return false
  const patterns = [
    /\bOR\s+1\s*=\s*1\b/i,
    /\bOR\s+'1'\s*=\s*'1'/i,
    /\bUNION\s+(?:ALL\s+)?SELECT\b/i,
    /'\s*OR\s+'\w*'\s*=\s*'\w*'/i,
    /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP)\b/i,
    /'\s*--/,
    /'\s*#/,
    /'\s*\/\*/,
    /\bAND\s+\(?\s*SLEEP\s*\(/i,
    /\bBENCHMARK\s*\(/i,
  ]
  return patterns.some(p => p.test(input))
}

function looksMalformed(input) {
  if (!input) return false
  const hasSqlKeyword = /\b(SELECT|UNION|FROM|WHERE|OR|AND|DROP)\b/i.test(input)
  const hasUnbalancedQuotes = (input.match(/'/g) || []).length % 2 === 1
  return hasSqlKeyword && hasUnbalancedQuotes && !looksLikeSqlInjection(input)
}

function pickSqliResultRows(input, scenario) {
  if (/\bUNION\b/i.test(input)) {
    return [...scenario.publicTableRows.slice(0, 2), ...scenario.sensitiveTableRows]
  }
  if (/\bOR\s+1\s*=\s*1\b/i.test(input) || /'\s*OR\s+'\w*'\s*=\s*'\w*'/i.test(input)) {
    return [...scenario.publicTableRows, ...scenario.sensitiveTableRows]
  }
  if (/;\s*SELECT/i.test(input)) return scenario.sensitiveTableRows
  return scenario.sensitiveTableRows
}

function renderRows(rows) {
  if (!rows || rows.length === 0) return '<p class="no-results">No results found.</p>'
  // Union of all columns across all rows — UNION SELECT * with mixed schemas
  // produces a wide result set. Without this, sensitive-table columns are
  // dropped because rows[0] (a public row) doesn't have them.
  const columns = Array.from(new Set(rows.flatMap(r => Object.keys(r))))
  return `<table class="results">
    <thead><tr>${columns.map(c => `<th>${escapeHtml(c)}</th>`).join('')}</tr></thead>
    <tbody>${rows.map(row =>
      `<tr>${columns.map(c => `<td>${escapeHtml(String(row[c] ?? ''))}</td>`).join('')}</tr>`
    ).join('')}</tbody>
  </table>`
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
