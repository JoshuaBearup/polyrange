// Auth + dependency precheck. Runs before the eval wizard so the user
// catches missing setup before the cost-and-time-bearing deploy phase.
//
// Each check returns { ok: boolean, value: string }. The dashboard render
// presents them as a table; failures get a fix-instruction sub-panel.

import { spawnSync, spawn } from 'node:child_process'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { password, confirm } from '@inquirer/prompts'
import {
  boxTop, boxLine, boxBlank, boxBottom, boxDivider, colors,
  padRightVisible, BOX_WIDTH,
} from './dashboard.mjs'

const PAD_LABEL = 30
const PAD_VALUE = 30

function row(label, value, ok) {
  const status = ok ? colors.green('OK') : colors.yellow('Needed')
  return padRightVisible(label, PAD_LABEL) + padRightVisible(value, PAD_VALUE) + status
}

function checkNode() {
  const v = process.versions.node
  const major = parseInt(v.split('.')[0], 10)
  return { ok: major >= 18, value: 'v' + v, name: 'Node.js', min: 'v18+ required' }
}

function checkFlyctl() {
  const r = spawnSync('flyctl', ['version'], { encoding: 'utf-8' })
  if (r.error || r.status !== 0) {
    return { ok: false, value: 'not installed', name: 'flyctl' }
  }
  const ver = (r.stdout || '').split('\n')[0].replace(/^flyctl\s+/, '').split(' ')[0]
  return { ok: true, value: ver, name: 'flyctl' }
}

function checkFlyAuth() {
  if (process.env.FLY_API_TOKEN) {
    return { ok: true, value: 'FLY_API_TOKEN set', name: 'flyctl auth' }
  }
  const r = spawnSync('flyctl', ['auth', 'whoami'], { encoding: 'utf-8' })
  if (r.error || r.status !== 0) {
    return { ok: false, value: 'not logged in', name: 'flyctl auth' }
  }
  return { ok: true, value: (r.stdout || '').trim(), name: 'flyctl auth' }
}

function checkAnthropicKey() {
  const k = process.env.ANTHROPIC_API_KEY || ''
  if (!k) return { ok: false, value: 'not set', name: 'ANTHROPIC_API_KEY' }
  const masked = k.slice(0, 7) + '...' + k.slice(-4)
  return { ok: true, value: masked, name: 'ANTHROPIC_API_KEY' }
}

async function checkDiskSpace(repoRoot) {
  const r = spawnSync('df', ['-h', repoRoot], { encoding: 'utf-8' })
  if (r.error || r.status !== 0) {
    return { ok: true, value: 'unknown', name: 'Disk space' }
  }
  const lines = (r.stdout || '').trim().split('\n')
  if (lines.length < 2) return { ok: true, value: 'unknown', name: 'Disk space' }
  const cols = lines[1].split(/\s+/)
  const avail = cols[3] || '?'
  return { ok: true, value: `${avail} free`, name: 'Disk space (runs/)' }
}

export async function runPrecheck({ repoRoot } = {}) {
  const root = repoRoot || process.cwd()
  const checks = [
    checkNode(),
    checkFlyctl(),
    checkFlyAuth(),
    checkAnthropicKey(),
    await checkDiskSpace(root),
  ]
  const allOk = checks.every(c => c.ok)
  const failed = checks.filter(c => !c.ok)
  return { checks, allOk, failed }
}

// Interactive remediation. For checks the user can fix in-session (API key,
// flyctl auth, nvm node switch), prompt and fix. For ones we can't (Node
// itself, flyctl install), explain and return false.
export async function tryFixInteractively(result, { repoRoot } = {}) {
  for (const c of result.failed) {
    const fixed = await tryFixOne(c, { repoRoot })
    if (!fixed) return false
  }
  return true
}

async function tryFixOne(check, { repoRoot }) {
  switch (check.name) {
    case 'ANTHROPIC_API_KEY':
      return await fixAnthropicKey(repoRoot)
    case 'flyctl auth':
      return await fixFlyAuth()
    case 'flyctl':
      console.log(colors.yellow('  flyctl is not installed. Install it manually, then re-run.'))
      console.log('    macOS              brew install flyctl')
      console.log('    Linux / WSL        curl -L https://fly.io/install.sh | sh')
      console.log('    Windows / Docs     https://fly.io/docs/flyctl/install/')
      return false
    case 'Node.js':
      console.log(colors.yellow('  Node.js v18 or newer is required. Update and re-run.'))
      return false
    default:
      console.log(colors.yellow(`  Cannot auto-fix ${check.name}.`))
      return false
  }
}

async function fixAnthropicKey(repoRoot) {
  console.log()
  console.log(colors.bold('  ANTHROPIC_API_KEY is not set.'))
  console.log(colors.dim('  Used for per-deploy LLM theming. Get a key at https://console.anthropic.com'))
  const key = await password({
    message: 'Paste your ANTHROPIC_API_KEY:',
    mask: '*',
    validate: (v) => v.trim().startsWith('sk-ant-') ? true : 'expected an sk-ant-... key',
  })
  process.env.ANTHROPIC_API_KEY = key.trim()
  const save = await confirm({ message: 'Save to .env in the repo for future runs?', default: true })
  if (save) {
    const envPath = path.join(repoRoot || process.cwd(), '.env')
    const existing = await fs.readFile(envPath, 'utf-8').catch(() => '')
    const without = existing.split('\n').filter(l => !l.startsWith('ANTHROPIC_API_KEY=')).join('\n').replace(/\n+$/, '')
    const newContent = (without ? without + '\n' : '') + `ANTHROPIC_API_KEY=${key.trim()}\n`
    await fs.writeFile(envPath, newContent)
    await ensureGitignored(repoRoot || process.cwd(), '.env')
    console.log(colors.green('  Saved to .env (gitignored).  Set for this session and future runs.'))
  } else {
    console.log(colors.dim('  Key set for this session only.'))
  }
  return true
}

async function fixFlyAuth() {
  console.log()
  console.log(colors.bold('  flyctl is not authenticated.'))
  const ans = await confirm({ message: 'Run `fly auth login` now? (opens a browser)', default: true })
  if (!ans) {
    console.log(colors.dim('  Set FLY_API_TOKEN instead, or run `fly auth login` manually.'))
    return false
  }
  await new Promise((resolve) => {
    const child = spawn('fly', ['auth', 'login'], { stdio: 'inherit' })
    child.on('close', resolve)
  })
  // Re-verify.
  const recheck = checkFlyAuth()
  if (!recheck.ok) {
    console.log(colors.yellow('  Still not authenticated. Try again or set FLY_API_TOKEN.'))
    return false
  }
  console.log(colors.green(`  Authenticated as ${recheck.value}.`))
  return true
}

async function ensureGitignored(repoRoot, name) {
  const gitignorePath = path.join(repoRoot, '.gitignore')
  const existing = await fs.readFile(gitignorePath, 'utf-8').catch(() => '')
  if (existing.split('\n').some((l) => l.trim() === name)) return
  const updated = (existing.endsWith('\n') || existing === '' ? existing : existing + '\n') + name + '\n'
  await fs.writeFile(gitignorePath, updated)
}

// Auto-load .env (if present) into process.env. Called from polyrange.mjs
// before precheck, so a saved key is available without the user remembering
// to source anything.
export async function loadDotEnv(repoRoot) {
  const envPath = path.join(repoRoot, '.env')
  const text = await fs.readFile(envPath, 'utf-8').catch(() => null)
  if (!text) return
  for (const line of text.split('\n')) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/)
    if (!m) continue
    const [, k, raw] = m
    if (process.env[k]) continue
    const v = raw.replace(/^["']|["']$/g, '')
    process.env[k] = v
  }
}

export function renderPrecheck(result) {
  const lines = []
  lines.push(boxTop('Precheck'))
  lines.push(boxBlank())
  for (const c of result.checks) {
    lines.push(boxLine(row(c.name, c.value, c.ok)))
  }
  lines.push(boxBlank())
  if (result.allOk) {
    lines.push(boxLine(colors.green('All checks passed.') + '   Press ENTER to continue.'))
    lines.push(boxBottom())
    return lines.join('\n')
  }
  // Fix instructions for each failed check.
  for (const c of result.failed) {
    lines.push(boxDivider(fixHeading(c.name)))
    lines.push(boxBlank())
    for (const fixLine of fixInstructions(c.name)) lines.push(boxLine(fixLine))
    lines.push(boxBlank())
  }
  lines.push(boxLine(colors.dim('Re-run  node polyrange.mjs eval  once the items above are addressed.')))
  lines.push(boxBottom())
  return lines.join('\n')
}

function fixHeading(name) {
  switch (name) {
    case 'flyctl':         return 'Install flyctl'
    case 'flyctl auth':    return 'Fly authentication'
    case 'ANTHROPIC_API_KEY': return 'Anthropic key (used for per-deploy LLM theming)'
    case 'Node.js':        return 'Update Node.js'
    default: return `Fix ${name}`
  }
}

function fixInstructions(name) {
  switch (name) {
    case 'flyctl':
      return [
        '  macOS              brew install flyctl',
        '  Linux / WSL        curl -L https://fly.io/install.sh | sh',
        '  Windows / Docs     https://fly.io/docs/flyctl/install/',
      ]
    case 'flyctl auth':
      return [
        '  Option A           In a separate terminal, run',
        '                       fly auth login',
        '                     (opens a browser, signs you in, persists the token)',
        '',
        '  Option B           Set an API token',
        '                       export FLY_API_TOKEN=fly_...',
        '                     Get a token at  https://fly.io/user/personal_access',
      ]
    case 'ANTHROPIC_API_KEY':
      return [
        '                       export ANTHROPIC_API_KEY=sk-ant-...',
        '                     Get a key at  https://console.anthropic.com',
      ]
    case 'Node.js':
      return [
        '  PolyRange requires Node.js v20 or newer.',
        '  Install with nvm:  nvm install 20 && nvm use 20',
        '  Or download:       https://nodejs.org/en/download',
      ]
    default:
      return ['  See README.md for setup details.']
  }
}
