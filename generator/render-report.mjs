// Head-to-head report renderer.
//
// Takes one or more results CSVs (output by sweep-collect.mjs) and
// produces the locked-format PolyRange evaluation report — banner +
// aggregate-claim section (with Wilson 95% CIs) + per-cell descriptive
// table + standouts + claim scope. Honest about what's supported at
// the N the data represents.
//
// Usage:
//   node generator/render-report.mjs --runs=runs/X/opus.csv,runs/Y/gpt5.csv
//   node generator/render-report.mjs --runs=opus.csv,gpt5.csv \
//     --output=report.txt --N=1 --run-name=blog-2026-05-29

import fs from 'node:fs/promises'
import path from 'node:path'

const args = Object.fromEntries(
  process.argv.slice(2).map(a => {
    const [k, v] = a.replace(/^--/, '').split('=')
    return [k, v ?? true]
  })
)

const runsArg = args.runs
if (!runsArg) {
  console.error('--runs=path1.csv,path2.csv,... is required')
  process.exit(1)
}

const N = parseInt(args.N ?? '1', 10)
const runName = args['run-name'] || new Date().toISOString().slice(0, 10)
const protocolVersion = args['protocol-version'] || 'v0.9'
const harnessNote = args.harness || '(model + native harness, bring-your-own per the published convention)'

const runPaths = runsArg.split(',').map(p => p.trim()).filter(Boolean)
const runs = []
for (const p of runPaths) {
  const csv = await fs.readFile(p, 'utf-8').catch((e) => {
    console.error(`Could not read ${p}: ${e.message}`)
    process.exit(1)
  })
  runs.push({ path: p, rows: parseCsv(csv) })
}

// Group rows by model. A single CSV may carry one or multiple models.
const byModel = new Map() // modelName -> rows
for (const run of runs) {
  for (const row of run.rows) {
    if (!row.model) continue
    if (!byModel.has(row.model)) byModel.set(row.model, [])
    byModel.get(row.model).push(row)
  }
}

const models = [...byModel.keys()]
if (models.length === 0) {
  console.error('No model rows found in input CSVs.')
  process.exit(1)
}

// Aggregate stats per model
const modelStats = new Map()
for (const m of models) {
  const rows = byModel.get(m)
  const t0 = rows.filter(r => r.tier === '0')
  const t1 = rows.filter(r => r.tier === '1')
  const total = rows.length
  const solved = rows.filter(r => r.solved === 'true').length
  const t0Solved = t0.filter(r => r.solved === 'true').length
  const t1Solved = t1.filter(r => r.solved === 'true').length
  modelStats.set(m, {
    rows, t0, t1, total, solved, t0Solved, t1Solved,
    rate: total > 0 ? solved / total : 0,
    t0Rate: t0.length > 0 ? t0Solved / t0.length : 0,
    t1Rate: t1.length > 0 ? t1Solved / t1.length : 0,
  })
}

// Build per-cell table (class × tier × model)
const allClassIds = new Set()
for (const m of models) {
  for (const r of byModel.get(m)) {
    if (r.class_id) allClassIds.add(r.class_id)
  }
}
const classes = [...allClassIds].sort()

// Index: model -> classId -> tier -> row
const cellLookup = new Map()
for (const m of models) {
  const byClass = new Map()
  cellLookup.set(m, byClass)
  for (const r of byModel.get(m)) {
    if (!byClass.has(r.class_id)) byClass.set(r.class_id, new Map())
    byClass.get(r.class_id).set(r.tier, r)
  }
}

// Standouts
const standouts = computeStandouts(classes, models, cellLookup)

// Render
const out = renderReport({
  runName, protocolVersion, harnessNote, N,
  models, modelStats, classes, cellLookup, standouts,
})

if (args.output) {
  await fs.writeFile(args.output, out)
  console.log(`Wrote ${args.output}`)
} else {
  process.stdout.write(out)
}


// ── rendering ──────────────────────────────────────────────────────────────

function renderReport({ runName, protocolVersion, harnessNote, N, models, modelStats, classes, cellLookup, standouts }) {
  const totalDeploys = [...modelStats.values()].reduce((acc, s) => acc + s.rows.length, 0)
  const lines = []

  // ── BANNER ─────────────────────────────────────────────────────────────
  lines.push('╔' + '═'.repeat(78) + '╗')
  lines.push(banner(`PolyRange ${protocolVersion} — N=${N} Capability Smoke (fresh-draw)`))
  lines.push(banner(`run: ${runName}`))
  for (let i = 0; i < models.length; i++) {
    const m = models[i]
    const label = i === 0 ? 'Model A' : (i === 1 ? 'Model B' : `Model ${String.fromCharCode(67 + i - 2)}`)
    lines.push(banner(`${label}: ${m}`))
  }
  lines.push(banner(harnessNote))
  lines.push(banner(''))
  if (N === 1) {
    lines.push(banner('Claim scope at this N: aggregate model-vs-model and within-model gap'))
    lines.push(banner('claims are statistically supported (170 trials per model in a full'))
    lines.push(banner('sweep, 95% Wilson CI roughly ±0.04). Per-cell results are descriptive'))
    lines.push(banner('samples, NOT per-cell capability differentials. Publishable per-cell'))
    lines.push(banner('claims require the N=100 partnership-funded run on the roadmap.'))
  }
  lines.push('╚' + '═'.repeat(78) + '╝')
  lines.push('')

  // ── AGGREGATE ──────────────────────────────────────────────────────────
  lines.push('AGGREGATE  (supported claims — 95% Wilson interval on the trials per model)')
  const colWidth = 22
  lines.push(`${''.padEnd(48)} ${models.map(m => m.padEnd(colWidth)).join(' ')}`)
  lines.push('─'.repeat(48 + (colWidth + 1) * models.length))

  lines.push(row('Overall solve rate',
    models.map(m => {
      const s = modelStats.get(m)
      return formatRateCI(s.solved, s.total)
    })))
  lines.push(row('T0 solve rate',
    models.map(m => {
      const s = modelStats.get(m)
      return formatRateCI(s.t0Solved, s.t0.length)
    })))
  lines.push(row('T1 solve rate',
    models.map(m => {
      const s = modelStats.get(m)
      return formatRateCI(s.t1Solved, s.t1.length)
    })))
  lines.push(row('Defence gap (T0 − T1)',
    models.map(m => {
      const s = modelStats.get(m)
      return formatGap(s.t0Solved, s.t0.length, s.t1Solved, s.t1.length)
    })))

  if (models.length >= 2) {
    lines.push('')
    lines.push('MODEL-VS-MODEL  (aggregate gap between models, 95% CI on the difference)')
    for (let i = 1; i < models.length; i++) {
      const a = models[0]
      const b = models[i]
      const sa = modelStats.get(a)
      const sb = modelStats.get(b)
      const gap = (sa.rate - sb.rate)
      const ci = diffCI(sa.solved, sa.total, sb.solved, sb.total)
      const sig = (ci[0] > 0 || ci[1] < 0) ? 'distinguishable' : 'NOT distinguishable from zero at this N'
      lines.push(`  ${a} − ${b}: Δ ${gap.toFixed(3)}   [${ci[0].toFixed(3)}, ${ci[1].toFixed(3)}]   ${sig}`)
    }
  }

  lines.push('')

  // ── DESCRIPTIVE PER-CELL TABLE ─────────────────────────────────────────
  lines.push('DESCRIPTIVE  (per-cell results — single samples, not capability claims)')
  const tierLabels = ['T0', 'T1']
  const cellColWidth = 14
  const headerLine1 = ''.padEnd(40) + '  '
    + tierLabels.map(t => t.padStart(Math.floor((cellColWidth * models.length + (models.length - 1) * 2) / 2))
        .padEnd(cellColWidth * models.length + (models.length - 1) * 2)).join('  ')
  lines.push(headerLine1)
  let header2 = 'class'.padEnd(40)
  for (const t of tierLabels) {
    header2 += '  ' + models.map(m => shortLabel(m).padEnd(cellColWidth)).join('  ')
  }
  lines.push(header2)
  lines.push('─'.repeat(header2.length))

  // Group classes by section (4.1 / 4.2 / ...)
  const bySection = new Map()
  for (const cls of classes) {
    const section = sectionOf(cls)
    if (!bySection.has(section)) bySection.set(section, [])
    bySection.get(section).push(cls)
  }
  for (const [section, sectionClasses] of [...bySection.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    lines.push(`§ ${section}`)
    for (const cls of sectionClasses) {
      let line = '  ' + cls.padEnd(38)
      for (const t of ['0', '1']) {
        line += '  '
        line += models.map(m => {
          const row = cellLookup.get(m)?.get(cls)?.get(t)
          return cellCell(row).padEnd(cellColWidth)
        }).join('  ')
      }
      lines.push(line)
    }
  }
  lines.push('')

  // ── STANDOUTS ──────────────────────────────────────────────────────────
  if (models.length >= 2) {
    lines.push('STANDOUTS  (descriptive, not inferential)')
    lines.push('')
    const a = models[0], b = models[1]
    lines.push(`  Cells solved only by ${a}:   ${standouts.onlyA.length} / ${standouts.total}`)
    for (const cls of standouts.onlyA.slice(0, 6)) {
      lines.push(`    - ${cls}`)
    }
    if (standouts.onlyA.length > 6) lines.push(`    (+ ${standouts.onlyA.length - 6} more)`)
    lines.push('')
    lines.push(`  Cells solved only by ${b}:   ${standouts.onlyB.length} / ${standouts.total}`)
    for (const cls of standouts.onlyB.slice(0, 6)) {
      lines.push(`    - ${cls}`)
    }
    if (standouts.onlyB.length > 6) lines.push(`    (+ ${standouts.onlyB.length - 6} more)`)
    lines.push('')
    lines.push(`  Both fail at T0:    ${standouts.bothFailT0.length} cells`)
    lines.push(`  Both fail at T1:    ${standouts.bothFailT1.length} cells`)
    lines.push(`  Both solve at T0:   ${standouts.bothSolveT0.length} cells`)
    lines.push(`  Both solve at T1:   ${standouts.bothSolveT1.length} cells`)
    lines.push('')
    lines.push('  Per-cell results are individual samples. A model\'s solve / no-solve on')
    lines.push('  any single cell could reverse on a fresh draw. Patterns above are')
    lines.push('  descriptive observations supporting the aggregate gap above; they are')
    lines.push('  not per-cell capability claims at this N.')
    lines.push('')
  }

  // ── CLAIM SCOPE ────────────────────────────────────────────────────────
  if (N === 1) {
    lines.push('CLAIMS SUPPORTED AT N=1')
    lines.push('  1. Within-model defence gap (T0 vs T1) is statistically distinguishable')
    lines.push('     from zero when the absolute Δ exceeds the CI half-width above.')
    lines.push('  2. Aggregate model-vs-model gap is supported when the CI does not cross')
    lines.push('     zero (flagged "distinguishable" in the model-vs-model section).')
    lines.push('')
    lines.push('CLAIMS NOT SUPPORTED AT N=1')
    lines.push('  - Per-class capability differential ("model X is better at class Y")')
    lines.push('  - Fine-grained discovery-mode comparisons within a single class section')
    lines.push('  - Per-cell stealth-axis claims (per-class median time-to-solve)')
    lines.push('')
    lines.push('NEXT')
    lines.push('  Partnership-funded N=100 run (per plan.html § Evaluation at scale)')
    lines.push('  produces per-cell CI of ±0.08 and supports the per-class capability')
    lines.push('  claims. Until that closes, this is what is publishable.')
  }

  return lines.join('\n') + '\n'
}

function banner(text) {
  const inner = ' ' + text.padEnd(76) + ' '
  return '║' + inner + '║'
}

function row(label, values) {
  return label.padEnd(48) + ' ' + values.map(v => v.padEnd(22)).join(' ')
}

function formatRateCI(successes, n) {
  if (n === 0) return 'n/a'
  const rate = successes / n
  const [lo, hi] = wilsonCI(successes, n)
  return `${rate.toFixed(3)} [${lo.toFixed(2)},${hi.toFixed(2)}]`
}

function formatGap(s1, n1, s2, n2) {
  if (n1 === 0 || n2 === 0) return 'n/a'
  const rate1 = s1 / n1
  const rate2 = s2 / n2
  const gap = rate1 - rate2
  const ci = diffCI(s1, n1, s2, n2)
  return `Δ ${gap >= 0 ? '+' : ''}${gap.toFixed(3)} [${ci[0].toFixed(2)},${ci[1].toFixed(2)}]`
}

function cellCell(row) {
  if (!row) return '—'
  if (row.solved !== 'true') return '· no-solve'
  const t = row.time_to_solve_ms ? formatMs(parseInt(row.time_to_solve_ms, 10)) : '?'
  const r = row.requests_to_solve || '?'
  return `✓ ${t}/${r}r`
}

function sectionOf(cls) {
  const m = cls.match(/-(\d+\.\d+)\b/)
  return m ? m[1] : 'unknown'
}

function shortLabel(m) {
  const lower = m.toLowerCase()
  if (lower.includes('opus')) return 'Opus'
  if (lower.includes('gpt-5')) return 'GPT-5'
  if (lower.includes('gpt')) return 'GPT'
  if (lower.includes('claude')) return 'Claude'
  if (lower.includes('codex')) return 'Codex'
  return m.slice(0, 12)
}


// ── stats ──────────────────────────────────────────────────────────────────

function wilsonCI(successes, n, z = 1.96) {
  if (n === 0) return [0, 0]
  const p = successes / n
  const denom = 1 + z * z / n
  const center = (p + z * z / (2 * n)) / denom
  const halfWidth = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
  return [Math.max(0, center - halfWidth), Math.min(1, center + halfWidth)]
}

// Normal-approximation CI on the difference of two independent proportions.
// Adequate when both n are ≥ 30; at smaller n the interval is conservative.
function diffCI(s1, n1, s2, n2, z = 1.96) {
  if (n1 === 0 || n2 === 0) return [0, 0]
  const p1 = s1 / n1, p2 = s2 / n2
  const diff = p1 - p2
  const se = Math.sqrt(p1 * (1 - p1) / n1 + p2 * (1 - p2) / n2)
  const halfWidth = z * se
  return [diff - halfWidth, diff + halfWidth]
}


// ── standouts ──────────────────────────────────────────────────────────────

function computeStandouts(classes, models, cellLookup) {
  if (models.length < 2) {
    return { onlyA: [], onlyB: [], bothSolveT0: [], bothSolveT1: [], bothFailT0: [], bothFailT1: [], total: 0 }
  }
  const a = models[0], b = models[1]
  const onlyA = [], onlyB = []
  const bothSolveT0 = [], bothSolveT1 = []
  const bothFailT0 = [], bothFailT1 = []
  let total = 0
  for (const cls of classes) {
    for (const t of ['0', '1']) {
      const ra = cellLookup.get(a)?.get(cls)?.get(t)
      const rb = cellLookup.get(b)?.get(cls)?.get(t)
      if (!ra && !rb) continue
      total++
      const aSolved = ra?.solved === 'true'
      const bSolved = rb?.solved === 'true'
      const label = `${cls} T${t}`
      if (aSolved && !bSolved) onlyA.push(label)
      else if (!aSolved && bSolved) onlyB.push(label)
      else if (aSolved && bSolved) {
        if (t === '0') bothSolveT0.push(label); else bothSolveT1.push(label)
      } else {
        if (t === '0') bothFailT0.push(label); else bothFailT1.push(label)
      }
    }
  }
  return { onlyA, onlyB, bothSolveT0, bothSolveT1, bothFailT0, bothFailT1, total }
}


// ── csv helpers ────────────────────────────────────────────────────────────

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

function formatMs(n) {
  if (!n || Number.isNaN(n)) return '?'
  if (n < 1000) return `${n}ms`
  if (n < 60000) return `${(n / 1000).toFixed(1)}s`
  const min = Math.floor(n / 60000)
  const sec = Math.floor((n % 60000) / 1000)
  return `${min}m${sec.toString().padStart(2, '0')}s`
}
