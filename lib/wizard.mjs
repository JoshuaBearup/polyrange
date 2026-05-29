// Interactive setup wizard for `polyrange eval`. Walks the user through
// model label, tier selection, class selection, run-id, concurrency.
// Skipped when --yes plus the same flags are supplied on the command line.

import fs from 'node:fs/promises'
import path from 'node:path'
import { input, checkbox, confirm, Separator } from '@inquirer/prompts'
import {
  boxTop, boxBottom, boxLine, boxBlank, boxDivider, colors, formatDollars,
} from './dashboard.mjs'

export async function runWizard({ repoRoot, prefill = {} } = {}) {
  const root = repoRoot || process.cwd()

  console.log()
  console.log(colors.bold('PolyRange Eval Setup'))
  console.log()

  const model = prefill.model || await input({
    message: 'Model label (used as a column value in results and in the report banner):',
    default: 'opus-4-8',
    validate: (v) => v.trim().length > 0 ? true : 'required',
  })

  const tiersAns = prefill.tiers || await checkbox({
    message: 'Which defence tier(s)?',
    choices: [
      { name: 'T0  undefended', value: 0, checked: true },
      { name: 'T1  signature WAF plus class-conditional logic', value: 1, checked: true },
    ],
    required: true,
  })

  const allClasses = await listClasses(root)
  const classChoices = buildClassChoices(allClasses)

  const classesAns = prefill.classes || await checkbox({
    message: 'Which classes? (space toggle, a all, enter confirm)',
    choices: classChoices,
    required: true,
    pageSize: 25,
    loop: false,
  })

  const concurrency = prefill.concurrency || parseInt(await input({
    message: 'Deploy concurrency (parallel deploys, 3 stays under Anthropic rate limit):',
    default: '3',
    validate: (v) => /^\d+$/.test(v) && +v > 0 ? true : 'positive integer',
  }), 10)

  const today = new Date().toISOString().slice(0, 10)
  const runId = prefill.runId || await input({
    message: 'Run ID (used as the output directory name under runs/):',
    default: `${today}-${sanitiseSlug(model)}`,
    validate: (v) => /^[a-z0-9._-]+$/i.test(v) ? true : 'letters, digits, ., _, - only',
  })

  const cells = classesAns.length * tiersAns.length
  const estDollars = cells * 1.40
  const estMinutes = Math.ceil((cells * 70) / concurrency / 60)

  console.log()
  console.log(renderSummary({ model, tiers: tiersAns, classes: classesAns, runId, concurrency, cells, estDollars, estMinutes }))
  console.log()

  const proceed = prefill.yes || await confirm({ message: 'Proceed with deploy?', default: true })
  if (!proceed) return null

  return { model, tiers: tiersAns, classes: classesAns, runId, concurrency, cells }
}

function renderSummary({ model, tiers, classes, runId, concurrency, cells, estDollars, estMinutes }) {
  const lines = []
  lines.push(boxTop('Summary'))
  lines.push(boxBlank())
  lines.push(boxLine(field('Model label', model)))
  lines.push(boxLine(field('Tiers', tiers.map(t => `T${t}`).join('  '))))
  lines.push(boxLine(field('Classes', `${classes.length} selected`)))
  lines.push(boxLine(field('Concurrency', String(concurrency))))
  lines.push(boxLine(field('Run ID', runId)))
  lines.push(boxBlank())
  lines.push(boxDivider())
  lines.push(boxBlank())
  lines.push(boxLine(field('Cells to deploy', String(cells))))
  lines.push(boxLine(field('Estimated cost', `~${formatDollars(estDollars)}  (deploys only)`)))
  lines.push(boxLine(field('Estimated time', `~${estMinutes} min`)))
  lines.push(boxLine(field('Output directory', `runs/${runId}/`)))
  lines.push(boxBlank())
  lines.push(boxBottom())
  return lines.join('\n')
}

function field(label, value) {
  return `${label.padEnd(24)}${value}`
}

async function listClasses(root) {
  const entries = await fs.readdir(path.join(root, 'classes'))
  return entries.filter(n => n.startsWith('wstg-') && !n.startsWith('_')).sort()
}

function classSection(classId) {
  const m = classId.match(/-(4\.\d+)\./)
  return m ? m[1] : 'other'
}

const SECTION_TITLES = {
  '4.1':  '§ 4.1 Information Gathering',
  '4.2':  '§ 4.2 Configuration & Deployment Management',
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

function buildClassChoices(classes) {
  const bySection = new Map()
  for (const c of classes) {
    const s = classSection(c)
    if (!bySection.has(s)) bySection.set(s, [])
    bySection.get(s).push(c)
  }
  const out = []
  const sortedSections = [...bySection.keys()].sort((a, b) => {
    const [ax, ay] = a.split('.').map(Number)
    const [bx, by] = b.split('.').map(Number)
    return ax - bx || ay - by
  })
  for (const s of sortedSections) {
    out.push(new Separator(SECTION_TITLES[s] || `§ ${s}`))
    for (const c of bySection.get(s).sort()) {
      out.push({ name: '  ' + c, value: c, checked: true })
    }
  }
  return out
}

function sanitiseSlug(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9._-]/g, '-').slice(0, 40)
}
