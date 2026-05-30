// Live monitor — polls /__pr/signature on every deployed cell every 5s and
// renders the dashboard mockup with top bars, aggregate stats, per-section
// progress, recent solves, and a 30-minute solve sparkline.
//
// Resolves on Ctrl+C (finalises with current state) or when every cell has
// resolved (solved or marked stale).

import fs from 'node:fs/promises'
import path from 'node:path'
import {
  boxTop, boxBottom, boxLine, boxBlank, boxDivider, colors,
  progressBar, formatDuration, padRightVisible, sparkline, cursor,
  wilson95, formatProportion, BOX_WIDTH,
} from './dashboard.mjs'

const POLL_INTERVAL_MS = 5000
const IDLE_THRESHOLD_MS = 5 * 60 * 1000
const SPARK_BUCKET_MS = 60_000
const SPARK_BUCKETS = 30
const SPINNER = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
let spinnerFrame = 0
let lastPollAt = Date.now()

const SECTION_TITLES = {
  '4.1':  '§ 4.1 Information Gather',
  '4.2':  '§ 4.2 Configuration',
  '4.3':  '§ 4.3 Identity Mgmt',
  '4.4':  '§ 4.4 Authentication',
  '4.5':  '§ 4.5 Authorization',
  '4.6':  '§ 4.6 Session Mgmt',
  '4.7':  '§ 4.7 Input Validation',
  '4.8':  '§ 4.8 Error Handling',
  '4.9':  '§ 4.9 Cryptography',
  '4.10': '§ 4.10 Business Logic',
  '4.11': '§ 4.11 Client-side',
  '4.12': '§ 4.12 API',
}

function classSection(classId) {
  const m = classId.match(/-(4\.\d+)\./)
  return m ? m[1] : 'other'
}

export async function runMonitor({ repoRoot, runDir, runId, modelLabel, cells }) {
  const root = repoRoot || process.cwd()
  const targetDir = runDir || path.join(root, 'runs', runId)

  // Initial state per cell.
  const state = new Map()
  for (const c of cells) {
    state.set(`${c.class_id}:t${c.tier}`, {
      class_id: c.class_id,
      tier: parseInt(c.tier, 10),
      url: c.url,
      canary: c.canary,
      control_key: c.control_key,
      status: 'pending',         // pending | working | idle | solved | failed
      lastObservedRequests: 0,
      lastChangeAt: Date.now(),
      sig: null,
      solveTime: null,
      durationMs: null,
      requestsToSolve: null,
      solvePayload: null,
    })
  }

  const startedAt = Date.now()
  const solveEvents = []       // array of {timestamp, classId, tier, durationMs, requests}

  process.stdout.write(cursor.hide)

  let lastDrawnLines = 0
  let stopped = false
  let userInterrupted = false

  // Handle Ctrl+C cleanly.
  const onSigInt = () => {
    userInterrupted = true
    stopped = true
  }
  process.on('SIGINT', onSigInt)

  // Raw-mode key listener for ^R refresh and ^Q abort.
  if (process.stdin.isTTY) {
    process.stdin.setRawMode?.(true)
    process.stdin.resume()
    process.stdin.on('data', (buf) => {
      const k = buf[0]
      if (k === 3 || k === 17) {       // ^C or ^Q
        userInterrupted = true
        stopped = true
      } else if (k === 18) {            // ^R
        // Force immediate refresh by triggering poll loop.
        pokePoll()
      }
    })
  }

  let pokeResolve = null
  function pokePoll() {
    if (pokeResolve) { pokeResolve(); pokeResolve = null }
  }
  function waitForNextTick() {
    return new Promise((resolve) => {
      pokeResolve = resolve
      setTimeout(() => {
        if (pokeResolve === resolve) { pokeResolve = null; resolve() }
      }, POLL_INTERVAL_MS)
    })
  }

  const render = () => {
    const panel = renderPanel(state, { startedAt, runId, modelLabel, solveEvents })
    process.stdout.write(cursor.clearScreen + panel + '\n')
  }

  // First draw immediately, then poll loop.
  render()

  while (!stopped) {
    await pollAll(state, solveEvents)
    render()
    if (allResolved(state)) break
    await waitForNextTick()
  }

  // Restore terminal state before any further output.
  if (process.stdin.isTTY) {
    process.stdin.setRawMode?.(false)
    process.stdin.pause()
  }
  process.removeListener('SIGINT', onSigInt)
  process.stdout.write(cursor.show)
  console.log()

  // Write results.csv.
  const resultsPath = await writeResults(targetDir, modelLabel, state)
  console.log(colors.dim(`  Results written to ${path.relative(process.cwd(), resultsPath)}`))
  if (userInterrupted) console.log(colors.dim('  Interrupted by user; unresolved cells recorded as no-solve.'))

  return {
    resultsPath,
    cells: [...state.values()],
    interrupted: userInterrupted,
  }
}

function allResolved(state) {
  for (const cell of state.values()) {
    if (cell.status !== 'solved' && cell.status !== 'failed' && cell.status !== 'idle') return false
  }
  return false  // Never auto-finalise; rely on user ^C. Easier than guessing.
}

async function pollAll(state, solveEvents) {
  lastPollAt = Date.now()
  const tasks = []
  for (const cell of state.values()) {
    if (cell.status === 'solved' || cell.status === 'failed') continue
    tasks.push(pollOne(cell, solveEvents))
  }
  await Promise.allSettled(tasks)
}

async function pollOne(cell, solveEvents) {
  if (!cell.url || !cell.control_key) {
    cell.status = 'failed'
    return
  }
  const url = cell.url.replace(/\/$/, '') + '/__pr/signature'
  try {
    const r = await fetch(url, { headers: { 'x-pr-control': cell.control_key }, signal: AbortSignal.timeout(8000) })
    if (!r.ok) {
      cell.status = 'failed'
      return
    }
    const sig = await r.json()
    cell.sig = sig
    if (sig.requests > cell.lastObservedRequests) {
      cell.lastChangeAt = Date.now()
      cell.lastObservedRequests = sig.requests
    }
    if (sig.solved && cell.status !== 'solved') {
      cell.status = 'solved'
      cell.solveTime = Date.now()
      cell.durationMs = sig.durationMs ?? sig.timeToSolveMs ?? null
      cell.requestsToSolve = sig.requestsInSession ?? sig.requestsToSolve ?? sig.requests ?? null
      cell.solvePayload = sig.solvePayload || null
      solveEvents.push({
        timestamp: cell.solveTime,
        classId: cell.class_id,
        tier: cell.tier,
        durationMs: cell.durationMs,
        requests: cell.requestsToSolve,
      })
    } else if (!sig.solved) {
      cell.status = (Date.now() - cell.lastChangeAt < IDLE_THRESHOLD_MS) ? 'working' : 'idle'
    }
  } catch {
    // Network blip — leave status as-is.
  }
}

function renderPanel(state, { startedAt, runId, modelLabel, solveEvents }) {
  const lines = []
  spinnerFrame = (spinnerFrame + 1) % SPINNER.length
  const spin = SPINNER[spinnerFrame]

  const monitorElapsed = formatDuration(Date.now() - startedAt)

  // Agent elapsed = time since the earliest first-request landed on any cell.
  // This is what the user actually cares about: "how long has the agent been
  // working?", not "how long since I pressed ENTER on the monitor."
  let earliestFirstReq = null
  for (const c of state.values()) {
    const f = c.sig?.firstRequestAt
    if (f && (!earliestFirstReq || f < earliestFirstReq)) earliestFirstReq = f
  }
  const agentElapsed = earliestFirstReq ? formatDuration(Date.now() - earliestFirstReq) : 'waiting'
  const secsSincePoll = Math.floor((Date.now() - lastPollAt) / 1000)
  const nextPollIn = Math.max(0, Math.ceil((POLL_INTERVAL_MS - (Date.now() - lastPollAt)) / 1000))

  let solved = 0, working = 0, idle = 0, pending = 0
  for (const c of state.values()) {
    if (c.status === 'solved') solved++
    else if (c.status === 'working') working++
    else if (c.status === 'idle') idle++
    else pending++
  }
  const total = state.size
  const resolved = solved
  const resolvedRate = resolved > 0 ? solved / resolved : 0
  const [ciLow, ciHi] = wilson95(solved, resolved)

  lines.push(boxTop(`Monitor ${spin}  ${modelLabel || '?'}  ${runId}  ·  agent ${agentElapsed}  ·  poll in ${nextPollIn}s`))
  lines.push(boxBlank())
  lines.push(boxLine('Solved   ' + progressBar(solved, total, { width: 36 })))
  lines.push(boxLine('Working  ' + progressBar(working, total, { width: 36 })))
  lines.push(boxLine('Idle     ' + progressBar(idle + pending, total, { width: 36 })))
  lines.push(boxBlank())

  // Aggregate stats and per-section table side by side.
  const aggregate = aggregateRows(solved, resolved, working, idle, pending, state, ciLow, ciHi, solveEvents)
  const sections = sectionRows(state)
  const maxRows = Math.max(aggregate.length, sections.length)

  lines.push(boxDivider('Aggregate (running)'))
  for (let i = 0; i < maxRows; i++) {
    const a = aggregate[i] || ''
    const s = sections[i] || ''
    lines.push(splitLine(a, s))
  }
  lines.push(boxBlank())

  lines.push(boxDivider('Recent solves'))
  lines.push(boxBlank())
  const recent = solveEvents.slice(-8).reverse()
  if (recent.length === 0) {
    lines.push(boxLine(colors.dim('  (none yet)')))
  } else {
    for (const ev of recent) {
      const ago = formatAgo(Date.now() - ev.timestamp)
      lines.push(boxLine(`  ${colors.green('ok')}  T${ev.tier}  ${padRightVisible(ev.classId, 38)}${padRightVisible(formatDuration(ev.durationMs), 9)}${padRightVisible(String(ev.requests || '?') + ' req', 10)}${ago}`))
    }
  }
  lines.push(boxBlank())

  // Activity sparkline.
  lines.push(boxDivider('Activity'))
  lines.push(boxBlank())
  lines.push(boxLine('  Solves over last 30 min'))
  const buckets = solveBuckets(solveEvents, SPARK_BUCKETS, SPARK_BUCKET_MS)
  const sparkRows = sparkline(buckets, { height: 4 })
  for (const row of sparkRows) lines.push(boxLine('  ' + row))
  lines.push(boxLine('  ' + colors.dim('30m       20m       10m         now')))
  lines.push(boxBlank())

  lines.push(boxDivider('Keys'))
  lines.push(boxBlank())
  lines.push(boxLine('  ^C  Finalise report with current state'))
  lines.push(boxLine('  ^R  Force refresh now'))
  lines.push(boxLine('  ^Q  Abort'))
  lines.push(boxBlank())
  lines.push(boxBottom())
  return lines.join('\n')
}

function aggregateRows(solved, resolvedDenom, working, idle, pending, state, ciLow, ciHi, solveEvents) {
  const total = state.size
  const rate = (resolvedDenom + idle) > 0 ? solved / (resolvedDenom + idle) : 0
  const t0Solved = [...state.values()].filter(c => c.tier === 0 && c.status === 'solved').length
  const t0Total = [...state.values()].filter(c => c.tier === 0).length
  const t1Solved = [...state.values()].filter(c => c.tier === 1 && c.status === 'solved').length
  const t1Total = [...state.values()].filter(c => c.tier === 1).length

  const durations = solveEvents.map(e => e.durationMs).filter(Boolean).sort((a, b) => a - b)
  const reqs = solveEvents.map(e => e.requests).filter(Boolean).sort((a, b) => a - b)
  const med = (arr) => arr.length ? arr[Math.floor(arr.length / 2)] : null

  const lastSolveAgo = solveEvents.length > 0 ? formatAgo(Date.now() - solveEvents[solveEvents.length - 1].timestamp) : '—'
  const defenceGap = (t0Total && t1Total) ? (t0Solved / t0Total) - (t1Solved / t1Total) : null

  return [
    `Solve rate     ${formatProportion(rate)}`,
    `Lower CI       ${formatProportion(ciLow)}`,
    `Upper CI       ${formatProportion(ciHi)}`,
    `Median time    ${med(durations) ? formatDuration(med(durations)) : '—'}`,
    `Median reqs    ${med(reqs) ?? '—'}`,
    `T0 solved      ${t0Solved}/${t0Total}`,
    `T1 solved      ${t1Solved}/${t1Total}`,
    `Defence gap    ${defenceGap !== null ? (defenceGap >= 0 ? '+' : '') + defenceGap.toFixed(2) : '—'}`,
    `Last solve     ${lastSolveAgo}`,
  ]
}

function sectionRows(state) {
  const counts = new Map()
  for (const c of state.values()) {
    const s = classSection(c.class_id)
    const cur = counts.get(s) || { solved: 0, total: 0 }
    cur.total++
    if (c.status === 'solved') cur.solved++
    counts.set(s, cur)
  }
  const sortedSections = [...counts.keys()].sort((a, b) => {
    const [ax, ay] = a.split('.').map(Number)
    const [bx, by] = b.split('.').map(Number)
    return ax - bx || ay - by
  })
  return sortedSections.map((s) => {
    const { solved, total } = counts.get(s)
    const title = padRightVisible(SECTION_TITLES[s] || `§ ${s}`, 24)
    const ratio = total ? solved / total : 0
    const bar = barFromRatio(ratio, 10)
    return `${title}${bar}  ${solved}/${total}`
  })
}

function barFromRatio(ratio, width) {
  const filled = Math.round(ratio * width)
  return '█'.repeat(filled) + '░'.repeat(Math.max(0, width - filled))
}

function splitLine(left, right) {
  const inner = BOX_WIDTH - 4
  const half = Math.floor(inner / 2)
  const leftCell = padRightVisible(' ' + left, half + 1)
  const rightCell = padRightVisible('  ' + right, inner - half)
  return '│' + leftCell + rightCell + ' │'
}

function formatAgo(ms) {
  if (ms < 60_000) return 'just now'
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`
  return `${Math.floor(ms / 3_600_000)}h ago`
}

function solveBuckets(events, nBuckets, bucketMs) {
  const now = Date.now()
  const buckets = new Array(nBuckets).fill(0)
  for (const ev of events) {
    const age = now - ev.timestamp
    if (age < 0 || age > nBuckets * bucketMs) continue
    const idx = nBuckets - 1 - Math.floor(age / bucketMs)
    if (idx >= 0 && idx < nBuckets) buckets[idx]++
  }
  return buckets
}

async function writeResults(runDir, modelLabel, state) {
  const slug = String(modelLabel || 'model').replace(/[^a-z0-9._-]/gi, '-').slice(0, 40)
  const resultsPath = path.join(runDir, `results-${slug}.csv`)
  const header = 'class_id,tier,model,url,canary,solved,duration_ms,requests_to_solve,total_requests,solved_via,solve_method,solve_path,solve_query,collected_at\n'
  const lines = [header]
  for (const cell of state.values()) {
    const solved = cell.status === 'solved'
    const sig = cell.sig || {}
    const cols = [
      cell.class_id,
      cell.tier,
      modelLabel || '',
      cell.url,
      cell.canary,
      solved,
      solved ? (cell.durationMs ?? '') : '',
      solved ? (cell.requestsToSolve ?? '') : '',
      sig.requests ?? '',
      sig.solvedVia ?? '',
      cell.solvePayload?.method ?? '',
      cell.solvePayload?.path ?? '',
      cell.solvePayload?.query ?? '',
      new Date().toISOString(),
    ]
    lines.push(cols.map(csvVal).join(','))
  }
  await fs.writeFile(resultsPath, lines.join('\n') + '\n')
  return resultsPath
}

function csvVal(v) {
  const s = String(v ?? '')
  return /[,"\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}
