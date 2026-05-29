#!/usr/bin/env node
// PolyRange unified CLI. Subcommand dispatcher.
//
//   node polyrange.mjs eval [--model=X --tier=0,1 --classes=all --run-id=X --yes]
//   node polyrange.mjs deploy [--tier=0 --classes=all --run-id=X --concurrency=3]
//   node polyrange.mjs monitor --run-id=X --model=X
//   node polyrange.mjs report --runs=A,B [--output=file]
//   node polyrange.mjs destroy --run-id=X
//   node polyrange.mjs one --class=X --tier=0 [--ephemeral]

import fs from 'node:fs/promises'
import path from 'node:path'
import { spawn } from 'node:child_process'
import { confirm } from '@inquirer/prompts'
import { runPrecheck, renderPrecheck, tryFixInteractively, loadDotEnv } from './lib/precheck.mjs'
import { runWizard } from './lib/wizard.mjs'
import { runDeployScreen } from './lib/deploy-screen.mjs'
import { runHandoffScreen } from './lib/handoff-screen.mjs'
import { runMonitor } from './lib/monitor.mjs'
import { runReport } from './lib/report.mjs'
import { colors, boxTop, boxBottom, boxLine, boxBlank } from './lib/dashboard.mjs'

const argv = process.argv.slice(2)
const sub = argv[0]
const flags = parseFlags(argv.slice(1))

const REPO_ROOT = process.cwd()

function parseFlags(args) {
  const out = {}
  for (const a of args) {
    if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split('=')
      out[k] = v === undefined ? true : v
    }
  }
  return out
}

function help() {
  console.log(`
PolyRange — contamination-resistant offensive AI evaluation framework

USAGE
  node polyrange.mjs <command> [options]

COMMANDS
  eval      End-to-end: precheck, deploy, hand-off prompt, monitor, report
  deploy    Just deploy infrastructure (writes manifest.csv)
  monitor   Live monitor over an existing run-id's manifest
  report    Combine 1+ results CSVs into head-to-head report
  destroy   Tear down deploys for a run-id
  one       Single-class deploy (wraps generator/deploy.mjs)

EXAMPLES
  node polyrange.mjs eval
  node polyrange.mjs eval --model=opus-4-8 --tier=0,1 --classes=all --run-id=blog-opus --yes
  node polyrange.mjs report --runs=runs/blog-opus,runs/blog-gpt5 --output=blog-report.txt
  node polyrange.mjs destroy --run-id=blog-opus
`)
}

async function main() {
  if (!sub || sub === 'help' || sub === '-h' || sub === '--help') {
    help()
    process.exit(0)
  }
  try {
    switch (sub) {
      case 'eval':    return await cmdEval()
      case 'deploy':  return await cmdDeploy()
      case 'monitor': return await cmdMonitor()
      case 'report':  return await cmdReport()
      case 'destroy': return await cmdDestroy()
      case 'one':     return await cmdOne()
      default:
        console.error(`Unknown command: ${sub}`)
        help()
        process.exit(2)
    }
  } catch (err) {
    if (err && err.name === 'ExitPromptError') {
      console.log()
      console.log(colors.dim('  Aborted.'))
      process.exit(130)
    }
    console.error(err.stack || err.message || err)
    process.exit(1)
  }
}

async function cmdEval() {
  // 1) Precheck (with interactive fix-it loop on failures)
  await loadDotEnv(REPO_ROOT)
  let precheck = await runPrecheck({ repoRoot: REPO_ROOT })
  console.log(renderPrecheck(precheck))
  if (!precheck.allOk) {
    const fixed = await tryFixInteractively(precheck, { repoRoot: REPO_ROOT })
    if (!fixed) process.exit(1)
    precheck = await runPrecheck({ repoRoot: REPO_ROOT })
    console.log(renderPrecheck(precheck))
    if (!precheck.allOk) {
      console.log(colors.red('  Some checks still fail. Address them and re-run.'))
      process.exit(1)
    }
  }
  if (!flags.yes) {
    await confirm({ message: 'Continue to setup?', default: true })
  }

  // 2) Setup wizard (skipped if all flags supplied)
  const prefill = {}
  if (flags.model) prefill.model = flags.model
  if (flags.tier) prefill.tiers = String(flags.tier).split(',').map(s => parseInt(s, 10))
  if (flags.classes) prefill.classes = await resolveClassList(flags.classes)
  if (flags.concurrency) prefill.concurrency = parseInt(flags.concurrency, 10)
  if (flags['run-id']) prefill.runId = flags['run-id']
  if (flags.yes) prefill.yes = true

  const cfg = await runWizard({ repoRoot: REPO_ROOT, prefill })
  if (!cfg) { console.log(colors.dim('  Cancelled.')); return }

  // 3) Deploy
  const deployResult = await runDeployScreen({
    repoRoot: REPO_ROOT,
    classes: cfg.classes,
    tiers: cfg.tiers,
    runId: cfg.runId,
    concurrency: cfg.concurrency,
  })
  if (deployResult.deployed === 0) {
    console.log(colors.red('  No cells deployed successfully. Aborting.'))
    return
  }

  // 4) Hand-off prompt
  const handoff = await runHandoffScreen({
    repoRoot: REPO_ROOT,
    runId: cfg.runId,
    runDir: deployResult.runDir,
    modelLabel: cfg.model,
    deployed: deployResult.deployed,
    totalCost: deployResult.totalCost,
    wallMs: deployResult.wallMs,
  })

  // 5) Live monitor
  const monitorResult = await runMonitor({
    repoRoot: REPO_ROOT,
    runDir: deployResult.runDir,
    runId: cfg.runId,
    modelLabel: cfg.model,
    cells: handoff.deployedRows,
  })

  // 6) Report
  const reportPath = path.join(deployResult.runDir, 'report.txt')
  const report = await runReport({
    resultsCsvs: [monitorResult.resultsPath],
    outputPath: reportPath,
    banner: { runIds: cfg.runId },
  })
  console.log(report.txt)
  console.log()
  console.log(colors.dim(`  Report written to ${path.relative(REPO_ROOT, reportPath)}`))
  console.log()

  // 7) Teardown prompt
  const tearDown = await confirm({ message: 'Tear down deploys now?', default: false })
  if (tearDown) {
    await runDestroy(cfg.runId)
  } else {
    console.log(colors.dim(`  Deploys left up.  Tear down later with:  node polyrange.mjs destroy --run-id=${cfg.runId}`))
  }
}

async function cmdDeploy() {
  await loadDotEnv(REPO_ROOT)
  let precheck = await runPrecheck({ repoRoot: REPO_ROOT })
  console.log(renderPrecheck(precheck))
  if (!precheck.allOk) {
    const fixed = await tryFixInteractively(precheck, { repoRoot: REPO_ROOT })
    if (!fixed) process.exit(1)
    precheck = await runPrecheck({ repoRoot: REPO_ROOT })
    if (!precheck.allOk) process.exit(1)
  }

  const prefill = {}
  if (flags.model) prefill.model = flags.model
  if (flags.tier) prefill.tiers = String(flags.tier).split(',').map(s => parseInt(s, 10))
  if (flags.classes) prefill.classes = await resolveClassList(flags.classes)
  if (flags.concurrency) prefill.concurrency = parseInt(flags.concurrency, 10)
  if (flags['run-id']) prefill.runId = flags['run-id']
  if (flags.yes) prefill.yes = true
  const cfg = await runWizard({ repoRoot: REPO_ROOT, prefill })
  if (!cfg) return
  await runDeployScreen({
    repoRoot: REPO_ROOT,
    classes: cfg.classes,
    tiers: cfg.tiers,
    runId: cfg.runId,
    concurrency: cfg.concurrency,
  })
}

async function cmdMonitor() {
  if (!flags['run-id']) throw new Error('--run-id=X is required')
  if (!flags.model) throw new Error('--model=X is required')
  const runDir = path.join(REPO_ROOT, 'runs', flags['run-id'])
  const csvPath = path.join(runDir, 'manifest.csv')
  const rows = await readManifestCsv(csvPath)
  const deployedRows = rows.filter(r => r.status === 'deployed' && r.url)
  await runMonitor({
    repoRoot: REPO_ROOT,
    runDir,
    runId: flags['run-id'],
    modelLabel: flags.model,
    cells: deployedRows,
  })
}

async function cmdReport() {
  if (!flags.runs) throw new Error('--runs=A,B,... is required (paths to run directories or CSVs)')
  const paths = String(flags.runs).split(',').map(s => s.trim()).filter(Boolean)
  const resolved = []
  for (const p of paths) {
    const abs = path.resolve(REPO_ROOT, p)
    const stat = await fs.stat(abs).catch(() => null)
    if (!stat) throw new Error(`Path not found: ${p}`)
    if (stat.isDirectory()) {
      // Find first results-*.csv inside.
      const entries = await fs.readdir(abs)
      const csv = entries.find(e => /^results-.*\.csv$/.test(e))
      if (!csv) throw new Error(`No results CSV in ${p}`)
      resolved.push(path.join(abs, csv))
    } else {
      resolved.push(abs)
    }
  }
  const outputPath = flags.output ? path.resolve(REPO_ROOT, flags.output) : null
  const { txt } = await runReport({ resultsCsvs: resolved, outputPath })
  console.log(txt)
  if (outputPath) console.log(colors.dim(`  Report written to ${path.relative(REPO_ROOT, outputPath)}`))
}

async function cmdDestroy() {
  if (!flags['run-id']) throw new Error('--run-id=X is required')
  await runDestroy(flags['run-id'])
}

async function cmdOne() {
  const cls = flags.class
  const tier = flags.tier ?? '0'
  if (!cls) throw new Error('--class=X is required')
  const args = ['generator/deploy.mjs', `--class=${cls}`, `--tier=${tier}`, '--target=fly']
  if (flags.ephemeral) args.push('--ephemeral')
  const child = spawn('node', args, { stdio: 'inherit', cwd: REPO_ROOT, env: process.env })
  await new Promise((resolve) => child.on('close', resolve))
}

async function runDestroy(runId) {
  console.log(colors.bold(`\nTearing down deploys for run ${runId}\n`))
  const child = spawn('node', ['generator/sweep-destroy.mjs', `--run-id=${runId}`], {
    stdio: 'inherit', cwd: REPO_ROOT, env: process.env,
  })
  await new Promise((resolve) => child.on('close', resolve))
}

async function resolveClassList(spec) {
  if (spec === 'all') {
    const all = await fs.readdir(path.join(REPO_ROOT, 'classes'))
    return all.filter(n => n.startsWith('wstg-') && !n.startsWith('_')).sort()
  }
  if (spec.startsWith('file:')) {
    const filePath = spec.slice('file:'.length)
    const content = await fs.readFile(filePath, 'utf-8')
    return content.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'))
  }
  if (spec.startsWith('section:')) {
    const sec = spec.slice('section:'.length)
    const all = await fs.readdir(path.join(REPO_ROOT, 'classes'))
    return all.filter(n => n.startsWith('wstg-') && !n.startsWith('_') && n.includes(`-${sec}.`)).sort()
  }
  return spec.split(',').map(s => s.trim()).filter(Boolean)
}

async function readManifestCsv(csvPath) {
  const text = await fs.readFile(csvPath, 'utf-8')
  const lines = text.split(/\r?\n/).filter(Boolean)
  if (lines.length === 0) return []
  const headers = lines[0].split(',')
  return lines.slice(1).map((line) => {
    const cols = splitCsv(line)
    const row = {}
    headers.forEach((h, i) => { row[h] = cols[i] ?? '' })
    return row
  })
}

function splitCsv(line) {
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

main()
