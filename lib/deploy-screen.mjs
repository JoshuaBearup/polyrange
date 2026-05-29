// Live deploy phase. Spawns N concurrent `node generator/deploy.mjs`
// subprocesses, watches their output, renders a dashboard panel that
// updates each second, writes manifest.csv as deploys complete.
//
// Returns the manifest path and a tally of deployed/failed.

import fs from 'node:fs/promises'
import path from 'node:path'
import { spawn } from 'node:child_process'
import {
  boxTop, boxBottom, boxLine, boxBlank, boxDivider, colors,
  progressBar, formatDollars, formatDuration, padRightVisible, cursor, BOX_WIDTH,
} from './dashboard.mjs'

const PHASE_PATTERNS = [
  { re: /^\[1\/5\]/,           phase: 'Generating theme' },
  { re: /^\[2\/5\]/,           phase: 'Generating scenario' },
  { re: /^\[3\/5\]/,           phase: 'Generating chrome' },
  { re: /^\[4\/5\]/,           phase: 'Generating decoys' },
  { re: /^\[5\/5\]/,           phase: 'Generating 404' },
  { re: /\[fly apps create\]/, phase: 'Creating Fly app' },
  { re: /\[fly deploy\]/,      phase: 'Building image' },
  { re: /\[fly status\]/,      phase: 'Waiting for boot' },
  { re: /container running/,   phase: 'Container running' },
  { re: /\[validate\]/,        phase: 'Validating' },
  { re: /Deploy complete/,     phase: 'Complete' },
]

export async function runDeployScreen({ repoRoot, classes, tiers, runId, concurrency, target = 'fly' }) {
  const root = repoRoot || process.cwd()
  const runDir = path.join(root, 'runs', runId)
  const logsDir = path.join(runDir, 'deploys')
  const csvPath = path.join(runDir, 'manifest.csv')

  await fs.mkdir(logsDir, { recursive: true })

  const csvHeader = 'class_id,tier,status,app_name,url,canary,control_key,cost_usd,duration_s,deployed_at,error\n'
  await fs.writeFile(csvPath, csvHeader)

  // Build the work queue: every (class, tier) pair.
  const cells = []
  for (const tier of tiers) {
    for (const classId of classes) cells.push({ classId, tier })
  }

  const totalCells = cells.length
  const startedAt = Date.now()

  const state = {
    queue: [...cells],
    inFlight: new Map(), // key=class:tier → { startedAt, phase, costFar, output }
    completed: [],       // most recent at end
    deployed: 0,
    failed: 0,
    totalCost: 0,
  }

  process.stdout.write(cursor.hide)

  const render = () => {
    const out = [cursor.clearScreen, renderPanel(state, { totalCells, startedAt, runId, concurrency }), ''].join('\n')
    process.stdout.write(out)
  }

  const tick = setInterval(render, 1000)

  await new Promise((resolve) => {
    const launchNext = () => {
      while (state.inFlight.size < concurrency && state.queue.length > 0) {
        const cell = state.queue.shift()
        const key = `${cell.classId}:t${cell.tier}`
        state.inFlight.set(key, { ...cell, startedAt: Date.now(), phase: 'Starting', costFar: 0, output: '' })
        runOneDeploy({ repoRoot: root, cell, logsDir, target, onChunk: (chunk) => {
          const slot = state.inFlight.get(key)
          if (!slot) return
          slot.output += chunk
          const lines = chunk.toString().split('\n')
          for (const line of lines) {
            for (const p of PHASE_PATTERNS) {
              if (p.re.test(line)) slot.phase = p.phase
            }
            const cm = line.match(/Est\. cost: \$([\d.]+)/)
            if (cm) slot.costFar = parseFloat(cm[1])
          }
        }}).then(async (result) => {
          state.inFlight.delete(key)
          state.completed.push(result)
          if (state.completed.length > 12) state.completed.shift()
          await appendRow(csvPath, result)
          if (result.status === 'deployed') {
            state.deployed++
            state.totalCost += result.cost_usd || 0
          } else {
            state.failed++
          }
          if (state.queue.length === 0 && state.inFlight.size === 0) {
            resolve()
          } else {
            launchNext()
          }
        })
      }
    }
    launchNext()
  })

  clearInterval(tick)
  render()
  process.stdout.write(cursor.show)

  const wallMs = Date.now() - startedAt
  console.log()
  console.log(colors.dim(`  Manifest: runs/${runId}/manifest.csv`))
  console.log(colors.dim(`  Per-deploy logs: runs/${runId}/deploys/`))
  console.log()

  return {
    csvPath,
    runDir,
    deployed: state.deployed,
    failed: state.failed,
    totalCost: state.totalCost,
    wallMs,
  }
}

function renderPanel(state, { totalCells, startedAt, runId, concurrency }) {
  const lines = []
  const elapsed = formatDuration(Date.now() - startedAt)
  const completedCount = state.deployed + state.failed
  const eta = etaEstimate(state, totalCells, startedAt)

  lines.push(boxTop(`Deploying  ${runId}  ${elapsed} elapsed  concurrency ${concurrency}`))
  lines.push(boxBlank())
  lines.push(boxLine('Progress   ' + progressBar(completedCount, totalCells, { width: 36, label: `${completedCount} / ${totalCells}    ${formatDollars(state.totalCost)}` })))
  lines.push(boxLine(`ETA        ${eta}`))
  lines.push(boxBlank())

  lines.push(boxDivider('In flight'))
  if (state.inFlight.size === 0) {
    lines.push(boxLine(colors.dim('  (none)')))
  } else {
    for (const [, slot] of state.inFlight) {
      const tag = `T${slot.tier}`
      const cls = padRightVisible(slot.classId, 36)
      const phase = padRightVisible(slot.phase, 22)
      const cost = padRightVisible(formatDollars(slot.costFar), 7)
      const dur = formatDuration(Date.now() - slot.startedAt)
      lines.push(boxLine(`${tag}  ${cls}${phase}${cost}${dur}`))
    }
  }
  lines.push(boxBlank())

  lines.push(boxDivider('Recent'))
  if (state.completed.length === 0) {
    lines.push(boxLine(colors.dim('  (waiting for first completion)')))
  } else {
    const recent = state.completed.slice(-6).reverse()
    for (const r of recent) {
      const ok = r.status === 'deployed'
      const tag = (ok ? colors.green('ok') : colors.red('xx')) + ' '
      const cls = padRightVisible(r.class_id, 36)
      const detail = ok
        ? `T${r.tier}  ${formatDollars(r.cost_usd)}  ${r.duration_s}s`
        : `T${r.tier}  ${(r.error || 'failed').slice(0, 28)}`
      lines.push(boxLine(`${tag} ${cls}${detail}`))
    }
  }
  lines.push(boxBlank())
  lines.push(boxBottom())
  return lines.join('\n')
}

function etaEstimate(state, totalCells, startedAt) {
  const completed = state.deployed + state.failed
  if (completed < 1) return 'computing'
  const elapsedMs = Date.now() - startedAt
  const remaining = totalCells - completed
  const remainingMs = (elapsedMs / completed) * remaining
  return formatDuration(remainingMs)
}

async function runOneDeploy({ repoRoot, cell, logsDir, target, onChunk }) {
  const { classId, tier } = cell
  const startedAt = Date.now()
  const deployedAt = new Date().toISOString()
  const logPath = path.join(logsDir, `${classId}-t${tier}.log`)
  const logFh = await fs.open(logPath, 'w')

  let output = ''
  const child = spawn('node', [
    'generator/deploy.mjs',
    `--class=${classId}`,
    `--target=${target}`,
    `--tier=${tier}`,
  ], { env: process.env, cwd: repoRoot })

  child.stdout.on('data', (d) => { output += d; logFh.write(d); onChunk(d) })
  child.stderr.on('data', (d) => { output += d; logFh.write(d); onChunk(d) })

  await new Promise((res) => child.on('close', res))
  await logFh.close()

  const duration_s = ((Date.now() - startedAt) / 1000).toFixed(1)
  const row = parseDeployOutput(output, classId, tier, duration_s, deployedAt)

  try {
    const localManifestPath = path.join(repoRoot, `manifest.${classId}.t${tier}.json`)
    const m = JSON.parse(await fs.readFile(localManifestPath, 'utf-8'))
    if (m.controlKey) row.control_key = m.controlKey
    await fs.unlink(localManifestPath).catch(() => {})
  } catch { /* manifest may not exist if deploy failed early */ }

  return row
}

function parseDeployOutput(output, classId, tier, duration_s, deployedAt) {
  const validated = /✓ Deploy complete.*VALIDATED at T/.test(output)
  const row = {
    class_id: classId,
    tier,
    status: validated ? 'deployed' : 'failed',
    app_name: '',
    url: '',
    canary: '',
    control_key: '',
    cost_usd: 0,
    duration_s,
    deployed_at: deployedAt,
    error: '',
  }
  const appMatch = output.match(/\[fly apps create\] ([a-z0-9-]+)/)
  if (appMatch) row.app_name = appMatch[1]
  const urlMatch = output.match(/deployed at (https?:\/\/[^\s]+)/)
  if (urlMatch) row.url = urlMatch[1]
  const canaryMatch = output.match(/Canary:\s+(pr_[a-f0-9]+)/)
  if (canaryMatch) row.canary = canaryMatch[1]
  const costMatch = output.match(/Est\. cost: \$([\d.]+)/)
  if (costMatch) row.cost_usd = parseFloat(costMatch[1])
  if (!validated) {
    const errMatch = output.match(/✗ (?:deploy failed|Solvability validation FAILED|Discovery validation FAILED|Negative-control validation FAILED): (.+?)(?:\n|$)/)
    if (errMatch) row.error = errMatch[1].slice(0, 240)
    else {
      const generic = output.match(/✗ (.+?)(?:\n|$)/m)
      if (generic) row.error = generic[1].slice(0, 240)
    }
  }
  return row
}

async function appendRow(csvPath, row) {
  const csvVal = (v) => {
    const s = String(v ?? '')
    return /[,"\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  const cols = [
    row.class_id, row.tier, row.status, row.app_name, row.url, row.canary,
    row.control_key, row.cost_usd, row.duration_s, row.deployed_at, row.error,
  ]
  await fs.appendFile(csvPath, cols.map(csvVal).join(',') + '\n')
}
