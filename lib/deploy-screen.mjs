// Live deploy phase. Spawns N concurrent `node generator/deploy.mjs`
// subprocesses, watches their output, renders a dashboard panel that
// updates each second, writes manifest.csv as deploys complete.
//
// Self-healing:
//   - Each cell gets up to maxRetries attempts (default 2).
//   - On failure, the Fly app (if created) is destroyed before retrying,
//     so a flaky run does not accrue cost.
//   - Failure categories are surfaced so the post-deploy triage table can
//     tell the user which failures are class-bugs vs scenario-flakes vs
//     infra issues.
//
// Returns the manifest path, tallies, and a per-cell failure record.

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

// Map failure phrases to a category. Order matters — first match wins.
const FAILURE_CATEGORIES = [
  { re: /Solvability validation FAILED/i,       category: 'validator',   retryable: true,
    advice: 'Canonical exploit did not recover the canary. Most often LLM-generated scenario content that breaks the exploit (e.g. SQL escaping); a retry rolls a fresh scenario.' },
  { re: /Discovery validation FAILED/i,         category: 'validator',   retryable: true,
    advice: 'Class discovery target was not reachable from the chrome. Usually a chrome-generation gap; retry usually fixes.' },
  { re: /Negative-control validation FAILED/i,  category: 'validator',   retryable: true,
    advice: 'Canary leaked into an ambient surface (DVWA-shaped). Retry rolls a fresh scenario.' },
  { re: /Class .* has no defences|does not implement T|incompatibility with T/i, category: 'class-config', retryable: false,
    advice: 'Class is not implemented at this tier. Pick a different tier or remove this class from the run.' },
  { re: /scenario does not validate|Zod/i,      category: 'scenario-gen', retryable: true,
    advice: 'LLM scenario gen produced an invalid scenario (Zod). Retry will reroll.' },
  { re: /\[fly apps create\].*(error|failed)/i, category: 'fly-create',  retryable: true,
    advice: 'Fly app creation failed. Probably transient; retry will try again.' },
  { re: /\[fly deploy\].*(error|failed)|build error|Build failed/i, category: 'build', retryable: true,
    advice: 'Docker build failed on Fly remote builder. Could be transient; retry will rebuild.' },
  { re: /ETIMEDOUT|ECONNRESET|fetch failed|getaddrinfo/i, category: 'network', retryable: true,
    advice: 'Network blip talking to Fly or Anthropic API. Retry should clear it.' },
  { re: /unauthorized|rate.limit|quota|insufficient.balance/i, category: 'auth-or-quota', retryable: false,
    advice: 'API auth, rate limit, or balance issue. Fix the credentials/quota and re-run.' },
]

function classifyFailure(errorMsg, output) {
  const haystack = (errorMsg || '') + '\n' + (output || '')
  for (const c of FAILURE_CATEGORIES) {
    if (c.re.test(haystack)) return { category: c.category, retryable: c.retryable, advice: c.advice }
  }
  return { category: 'other', retryable: true, advice: 'Unknown failure. A retry might clear it; if it persists, see the per-deploy log for details.' }
}

export async function runDeployScreen({
  repoRoot, classes, tiers, runId, concurrency,
  target = 'fly',
  maxRetries = 2,
}) {
  const root = repoRoot || process.cwd()
  const runDir = path.join(root, 'runs', runId)
  const logsDir = path.join(runDir, 'deploys')
  const csvPath = path.join(runDir, 'manifest.csv')

  await fs.mkdir(logsDir, { recursive: true })

  const csvHeader = 'class_id,tier,status,app_name,url,canary,control_key,cost_usd,duration_s,deployed_at,attempts,failure_category,error\n'
  await fs.writeFile(csvPath, csvHeader)

  // Build the work queue: every (class, tier) pair.
  const cells = []
  for (const tier of tiers) {
    for (const classId of classes) cells.push({ classId, tier, attempt: 1 })
  }

  const totalCells = cells.length
  const startedAt = Date.now()

  const state = {
    queue: [...cells],
    inFlight: new Map(),
    completed: [],
    failures: [],       // { class_id, tier, attempts, category, advice, error }
    deployed: 0,
    failed: 0,
    retrying: 0,
    totalCost: 0,
  }

  process.stdout.write(cursor.hide)

  const render = () => {
    const out = [cursor.clearScreen, renderPanel(state, { totalCells, startedAt, runId, concurrency, maxRetries }), ''].join('\n')
    process.stdout.write(out)
  }

  const tick = setInterval(render, 1000)

  await new Promise((resolve) => {
    const launchNext = () => {
      while (state.inFlight.size < concurrency && state.queue.length > 0) {
        const cell = state.queue.shift()
        const key = `${cell.classId}:t${cell.tier}:a${cell.attempt}`
        state.inFlight.set(key, {
          ...cell,
          startedAt: Date.now(),
          phase: cell.attempt > 1 ? `Retry ${cell.attempt}/${maxRetries + 1}` : 'Starting',
          costFar: 0,
          output: '',
        })
        runOneDeploy({ repoRoot: root, cell, logsDir, target, onChunk: (chunk) => {
          const slot = state.inFlight.get(key)
          if (!slot) return
          slot.output += chunk
          const lines = chunk.toString().split('\n')
          for (const line of lines) {
            for (const p of PHASE_PATTERNS) {
              if (p.re.test(line)) {
                slot.phase = cell.attempt > 1 ? `[retry ${cell.attempt}/${maxRetries + 1}] ${p.phase}` : p.phase
              }
            }
            const cm = line.match(/Est\. cost: \$([\d.]+)/)
            if (cm) slot.costFar = parseFloat(cm[1])
          }
        }}).then(async (result) => {
          state.inFlight.delete(key)
          result.attempt = cell.attempt

          if (result.status === 'deployed') {
            state.completed.push(result)
            if (state.completed.length > 12) state.completed.shift()
            await appendRow(csvPath, result)
            state.deployed++
            state.totalCost += result.cost_usd || 0
          } else {
            // Failed. Classify, optionally destroy, optionally retry.
            const fail = classifyFailure(result.error, result.output)
            result.category = fail.category
            result.advice = fail.advice

            // Always destroy the Fly app if we created one, regardless of retry.
            if (result.app_name && target === 'fly') {
              await destroyFlyApp(result.app_name).catch(() => {})
              result.destroyed = true
            }

            // Always charge the spent cost for failures too (LLM dollars).
            state.totalCost += result.cost_usd || 0

            if (fail.retryable && cell.attempt <= maxRetries) {
              // Re-queue with attempt++.
              state.queue.push({ classId: cell.classId, tier: cell.tier, attempt: cell.attempt + 1 })
              state.retrying++
              state.completed.push({ ...result, status: 'retrying' })
              if (state.completed.length > 12) state.completed.shift()
            } else {
              // Exhausted.
              state.completed.push(result)
              if (state.completed.length > 12) state.completed.shift()
              await appendRow(csvPath, result)
              state.failed++
              state.failures.push({
                class_id: result.class_id,
                tier: result.tier,
                attempts: cell.attempt,
                category: fail.category,
                advice: fail.advice,
                error: result.error,
              })
            }
          }

          if (state.queue.length === 0 && state.inFlight.size === 0) resolve()
          else launchNext()
        })
      }
    }
    launchNext()
  })

  clearInterval(tick)
  render()
  process.stdout.write(cursor.show)

  const wallMs = Date.now() - startedAt

  return {
    csvPath,
    runDir,
    deployed: state.deployed,
    failed: state.failed,
    failures: state.failures,
    totalCost: state.totalCost,
    wallMs,
  }
}

function renderPanel(state, { totalCells, startedAt, runId, concurrency, maxRetries }) {
  const lines = []
  const elapsed = formatDuration(Date.now() - startedAt)
  const completedCount = state.deployed + state.failed
  const eta = etaEstimate(state, totalCells, startedAt)

  lines.push(boxTop(`Deploying  ${runId}  ${elapsed} elapsed  concurrency ${concurrency}  retries ${maxRetries}`))
  lines.push(boxBlank())
  lines.push(boxLine('Progress   ' + progressBar(completedCount, totalCells, { width: 36, label: `${completedCount} / ${totalCells}    ${formatDollars(state.totalCost)}` })))
  lines.push(boxLine(`ETA        ${eta}`))
  if (state.retrying > 0) {
    lines.push(boxLine(colors.yellow(`Retrying   ${state.retrying} attempt(s) so far`)))
  }
  lines.push(boxBlank())

  lines.push(boxDivider('In flight'))
  if (state.inFlight.size === 0) {
    lines.push(boxLine(colors.dim('  (none)')))
  } else {
    for (const [, slot] of state.inFlight) {
      const tag = `T${slot.tier}`
      const cls = padRightVisible(slot.classId, 30)
      const phase = padRightVisible(slot.phase, 28)
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
      const tag = r.status === 'deployed' ? colors.green('ok')
        : r.status === 'retrying' ? colors.yellow('rt')
        : colors.red('xx')
      const cls = padRightVisible(r.class_id, 30)
      const attemptTag = (r.attempt && r.attempt > 1) ? `[a${r.attempt}] ` : ''
      const detail = r.status === 'deployed'
        ? `T${r.tier}  ${formatDollars(r.cost_usd)}  ${r.duration_s}s`
        : `T${r.tier}  ${attemptTag}${r.category || 'failed'}: ${(r.error || '').slice(0, 30)}`
      lines.push(boxLine(`${tag}  ${cls}${detail}`))
    }
  }
  lines.push(boxBlank())
  lines.push(boxBottom())
  return lines.join('\n')
}

export function renderFailureTriage(failures, options = {}) {
  if (!failures.length) return ''
  const lines = []
  lines.push(boxTop(`Deploy failures  ${failures.length} cell${failures.length === 1 ? '' : 's'} exhausted retries`))
  lines.push(boxBlank())

  // Group by category.
  const byCategory = new Map()
  for (const f of failures) {
    if (!byCategory.has(f.category)) byCategory.set(f.category, [])
    byCategory.get(f.category).push(f)
  }

  for (const [category, fs] of byCategory) {
    lines.push(boxDivider(category))
    lines.push(boxBlank())
    lines.push(boxLine(colors.dim('  ' + fs[0].advice)))
    lines.push(boxBlank())
    for (const f of fs) {
      lines.push(boxLine(`  ${padRightVisible(f.class_id + '  T' + f.tier, 38)}  attempts: ${f.attempts}`))
      if (f.error) {
        lines.push(boxLine(colors.dim('    ' + f.error.slice(0, BOX_WIDTH - 10))))
      }
    }
    lines.push(boxBlank())
  }

  if (options.partialOk) {
    lines.push(boxLine(colors.green('  Successful cells still deployed.  Continuing with those.')))
  } else {
    lines.push(boxLine(colors.red('  No cells succeeded.  Investigate failures above and re-run.')))
  }
  lines.push(boxBlank())
  lines.push(boxBottom())
  return lines.join('\n')
}

function etaEstimate(state, totalCells, startedAt) {
  const completed = state.deployed + state.failed
  if (completed < 1) return 'computing'
  const elapsedMs = Date.now() - startedAt
  const remaining = (totalCells - completed) + Math.max(0, state.queue.length - (totalCells - completed))
  const remainingMs = (elapsedMs / completed) * remaining
  return formatDuration(remainingMs)
}

async function runOneDeploy({ repoRoot, cell, logsDir, target, onChunk }) {
  const { classId, tier, attempt } = cell
  const startedAt = Date.now()
  const deployedAt = new Date().toISOString()
  const logPath = path.join(logsDir, `${classId}-t${tier}${attempt > 1 ? `-attempt${attempt}` : ''}.log`)
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
  row.output = output

  try {
    const localManifestPath = path.join(repoRoot, `manifest.${classId}.t${tier}.json`)
    const m = JSON.parse(await fs.readFile(localManifestPath, 'utf-8'))
    if (m.controlKey) row.control_key = m.controlKey
    await fs.unlink(localManifestPath).catch(() => {})
  } catch { /* manifest may not exist if deploy failed early */ }

  return row
}

async function destroyFlyApp(appName) {
  return new Promise((resolve) => {
    const child = spawn('flyctl', ['apps', 'destroy', appName, '-y'], {
      env: process.env,
      stdio: ['ignore', 'ignore', 'ignore'],
    })
    child.on('close', () => resolve())
    child.on('error', () => resolve())
  })
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
    category: '',
    attempts: 1,
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
    row.control_key, row.cost_usd, row.duration_s, row.deployed_at,
    row.attempt || row.attempts || 1, row.category || '', row.error,
  ]
  await fs.appendFile(csvPath, cols.map(csvVal).join(',') + '\n')
}
