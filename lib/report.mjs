// Report renderer — consumes 1+ results CSVs, computes aggregate stats with
// Wilson 95% CIs, and emits a dashboard-styled head-to-head report. Used by
// the `eval` finalisation step (single-model) and by the standalone
// `report` subcommand (1+ models).

import fs from 'node:fs/promises'
import path from 'node:path'
import {
  boxTop, boxBottom, boxLine, boxBlank, boxDivider, colors,
  padRightVisible, padLeftVisible, formatDuration, wilson95, formatProportion,
} from './dashboard.mjs'

const SECTION_TITLES = {
  '4.1':  '§ 4.1 Information Gathering',
  '4.2':  '§ 4.2 Configuration & Deployment',
  '4.3':  '§ 4.3 Identity Management',
  '4.4':  '§ 4.4 Authentication',
  '4.5':  '§ 4.5 Authorization',
  '4.6':  '§ 4.6 Session Management',
  '4.7':  '§ 4.7 Input Validation',
  '4.8':  '§ 4.8 Error Handling',
  '4.9':  '§ 4.9 Cryptography',
  '4.10': '§ 4.10 Business Logic',
  '4.11': '§ 4.11 Client-side Testing',
  '4.12': '§ 4.12 API Testing',
}

function classSection(classId) {
  const m = classId.match(/-(4\.\d+)\./)
  return m ? m[1] : 'other'
}

export async function runReport({ resultsCsvs, outputPath, banner }) {
  const datasets = []
  for (const p of resultsCsvs) {
    const rows = await readCsv(p)
    if (rows.length === 0) {
      console.warn(`  warning: ${p} has no rows`)
      continue
    }
    const modelLabel = rows[0].model || path.basename(p, '.csv').replace(/^results-/, '')
    datasets.push({ modelLabel, rows, source: p })
  }
  if (datasets.length === 0) throw new Error('No usable input CSVs')

  const txt = renderReport(datasets, banner)
  if (outputPath) {
    await fs.mkdir(path.dirname(outputPath), { recursive: true })
    await fs.writeFile(outputPath, txt)
  }
  return { txt, datasets }
}

function renderReport(datasets, banner) {
  const lines = []
  const runIds = banner?.runIds || datasets.map(d => path.basename(path.dirname(d.source))).filter((v, i, a) => a.indexOf(v) === i).join(', ')

  lines.push(boxTop(`PolyRange v0.9    Capability Smoke    ${runIds}`))
  lines.push(boxBlank())
  for (const d of datasets) {
    lines.push(boxLine(field('Model ' + d.modelLabel, `${d.rows.length} cells   single-session`)))
  }
  lines.push(boxLine(field('Protocol', 'fresh-draw infrastructure per model')))
  lines.push(boxLine(field('Intervals', '95% Wilson')))
  lines.push(boxBlank())

  // Aggregate panel.
  lines.push(boxDivider('Aggregate'))
  lines.push(boxBlank())
  lines.push(boxLine(aggregateHeader(datasets)))
  for (const row of aggregateRows(datasets)) lines.push(boxLine(row))
  lines.push(boxBlank())

  // Model-vs-model panel (only when 2+ models).
  if (datasets.length >= 2) {
    lines.push(boxDivider('Model-vs-model'))
    lines.push(boxBlank())
    for (const row of modelVsModelRows(datasets)) lines.push(boxLine(row))
    lines.push(boxBlank())
  }

  // Per-section descriptive table.
  lines.push(boxDivider('Descriptive (per-class — single samples)'))
  lines.push(boxBlank())
  for (const row of descriptiveTable(datasets)) lines.push(boxLine(row))
  lines.push(boxBlank())

  // Standouts.
  lines.push(boxDivider('Standouts'))
  lines.push(boxBlank())
  for (const row of standoutRows(datasets)) lines.push(boxLine(row))
  lines.push(boxBlank())

  // Claims supported / unsupported.
  lines.push(boxDivider('Claims at N=1'))
  lines.push(boxBlank())
  lines.push(boxLine('  Supported'))
  lines.push(boxLine('    - Within-model defence gap (T0 − T1)'))
  if (datasets.length >= 2) lines.push(boxLine('    - Aggregate model-vs-model gap'))
  lines.push(boxBlank())
  lines.push(boxLine('  Not supported'))
  lines.push(boxLine('    - Per-class capability differential'))
  lines.push(boxLine('    - Fine-grained discovery-mode comparison'))
  lines.push(boxLine('    - Per-class timing claims'))
  lines.push(boxBlank())
  lines.push(boxBottom())
  return lines.join('\n')
}

function field(label, value) {
  return `${padRightVisible(label, 20)}${value}`
}

function aggregateHeader(datasets) {
  const colWidth = 24
  const cells = datasets.map(d => padRightVisible(d.modelLabel, colWidth))
  return padRightVisible(' ', 24) + cells.join('')
}

function aggregateRows(datasets) {
  const rows = []
  const colWidth = 24
  const labels = [
    { key: 'overall', label: 'Overall solve rate' },
    { key: 't0',      label: 'T0 solve rate' },
    { key: 't1',      label: 'T1 solve rate' },
    { key: 'gap',     label: 'Defence gap (T0 − T1)' },
  ]
  for (const r of labels) {
    let line = padRightVisible(' ' + r.label, 24)
    for (const d of datasets) {
      const v = aggregateValue(d, r.key)
      line += padRightVisible(v, colWidth)
    }
    rows.push(line)
  }
  return rows
}

function aggregateValue(d, key) {
  const rows = d.rows
  let solved = 0, total = 0
  for (const row of rows) {
    if (key === 't0' && +row.tier !== 0) continue
    if (key === 't1' && +row.tier !== 1) continue
    if (key === 'gap') continue
    total++
    if (isSolved(row)) solved++
  }
  if (key === 'gap') {
    const t0Solved = rows.filter(r => +r.tier === 0 && isSolved(r)).length
    const t0Total  = rows.filter(r => +r.tier === 0).length
    const t1Solved = rows.filter(r => +r.tier === 1 && isSolved(r)).length
    const t1Total  = rows.filter(r => +r.tier === 1).length
    if (!t0Total || !t1Total) return '—'
    const p0 = t0Solved / t0Total
    const p1 = t1Solved / t1Total
    const diff = p0 - p1
    const sign = diff >= 0 ? '+' : ''
    return `${sign}${diff.toFixed(2)}`
  }
  if (total === 0) return '—'
  const [low, high] = wilson95(solved, total)
  return `${formatProportion(solved / total)} [${formatProportion(low)}, ${formatProportion(high)}]`
}

function modelVsModelRows(datasets) {
  const rows = []
  for (let i = 0; i < datasets.length; i++) {
    for (let j = i + 1; j < datasets.length; j++) {
      const a = datasets[i], b = datasets[j]
      const ar = solveRate(a)
      const br = solveRate(b)
      const diff = ar.rate - br.rate
      const sign = diff >= 0 ? '+' : ''
      rows.push(`  Δ ${a.modelLabel} − ${b.modelLabel}   ${sign}${diff.toFixed(2)}   (${formatProportion(ar.rate)} vs ${formatProportion(br.rate)})`)
    }
  }
  return rows
}

function solveRate(d) {
  let solved = 0, total = 0
  for (const r of d.rows) { total++; if (isSolved(r)) solved++ }
  return { solved, total, rate: total > 0 ? solved / total : 0 }
}

function descriptiveTable(datasets) {
  // Group by class, sorted by WSTG section.
  const classes = new Set()
  for (const d of datasets) for (const r of d.rows) classes.add(r.class_id)
  const sortedClasses = [...classes].sort((a, b) => {
    const sa = classSection(a), sb = classSection(b)
    if (sa !== sb) {
      const [ax, ay] = sa.split('.').map(Number)
      const [bx, by] = sb.split('.').map(Number)
      return ax - bx || ay - by
    }
    return a.localeCompare(b)
  })

  // Pick widths that fit the 72-char box inner width.
  // class column + 2 tier groups × n model cells.
  const innerWidth = 70
  const classW = datasets.length > 1 ? 26 : 36
  const tierBudget = innerWidth - classW
  const cellW = Math.max(8, Math.floor(tierBudget / (2 * datasets.length)))

  const rows = []
  // Header row.
  let head = ' ' + padRightVisible('class', classW)
  head += padRightVisible('T0', cellW * datasets.length)
  head += padRightVisible('T1', cellW * datasets.length)
  rows.push(colors.dim(head))
  // Sub-header showing which model column is which.
  if (datasets.length > 1) {
    let sub = ' ' + padRightVisible('', classW)
    for (const d of datasets) sub += padRightVisible(truncate(d.modelLabel, cellW - 1), cellW)
    for (const d of datasets) sub += padRightVisible(truncate(d.modelLabel, cellW - 1), cellW)
    rows.push(colors.dim(sub))
  }
  rows.push('')

  let curSection = ''
  for (const classId of sortedClasses) {
    const sec = classSection(classId)
    if (sec !== curSection) {
      curSection = sec
      rows.push(' ' + colors.dim(SECTION_TITLES[sec] || `§ ${sec}`))
    }
    let line = '  ' + padRightVisible(truncate(classId, classW - 2), classW - 1)
    for (const tier of [0, 1]) {
      for (const d of datasets) {
        const row = d.rows.find(r => r.class_id === classId && +r.tier === tier)
        if (!row) line += padRightVisible('—', cellW)
        else if (isSolved(row)) {
          const dur = row.duration_ms ? formatDuration(+row.duration_ms) : ''
          line += padRightVisible(truncate(`ok ${dur}`.trim(), cellW - 1), cellW)
        }
        else line += padRightVisible('·', cellW)
      }
    }
    rows.push(line)
  }
  return rows
}

function truncate(s, n) {
  if (s.length <= n) return s
  if (n <= 1) return s.slice(0, n)
  return s.slice(0, n - 1) + '…'
}

function standoutRows(datasets) {
  if (datasets.length < 2) {
    const d = datasets[0]
    const sr = solveRate(d)
    return [`  ${d.modelLabel} solved ${sr.solved} of ${sr.total} cells.`]
  }
  const rows = []
  // For each pair, classes solved by A only, B only, neither.
  const a = datasets[0], b = datasets[1]
  const aMap = new Map()
  const bMap = new Map()
  for (const r of a.rows) aMap.set(`${r.class_id}:${r.tier}`, isSolved(r))
  for (const r of b.rows) bMap.set(`${r.class_id}:${r.tier}`, isSolved(r))
  let onlyA = 0, onlyB = 0, neitherT0 = 0, neitherT1 = 0
  for (const key of new Set([...aMap.keys(), ...bMap.keys()])) {
    const aS = aMap.get(key)
    const bS = bMap.get(key)
    const tier = key.split(':t')[1] ? parseInt(key.split(':t')[1], 10) : parseInt(key.split(':')[1], 10)
    if (aS && !bS) onlyA++
    else if (bS && !aS) onlyB++
    else if (!aS && !bS) {
      if (tier === 0) neitherT0++
      else if (tier === 1) neitherT1++
    }
  }
  rows.push(`  ${padRightVisible('Solved only by ' + a.modelLabel, 40)}${onlyA} cells`)
  rows.push(`  ${padRightVisible('Solved only by ' + b.modelLabel, 40)}${onlyB} cells`)
  rows.push(`  ${padRightVisible('Both fail at T0', 40)}${neitherT0} cells`)
  rows.push(`  ${padRightVisible('Both fail at T1', 40)}${neitherT1} cells`)
  return rows
}

function isSolved(row) {
  const v = row.solved
  return v === true || v === 'true' || v === 'True' || v === '1'
}

async function readCsv(p) {
  const text = await fs.readFile(p, 'utf-8')
  const lines = text.split(/\r?\n/).filter(Boolean)
  if (lines.length === 0) return []
  const headers = splitCsvLine(lines[0])
  return lines.slice(1).map((line) => {
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
