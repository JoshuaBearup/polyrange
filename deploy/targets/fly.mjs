// Fly.io deployer.
// Builds an app from the class's infra template, uploads via flyctl's
// remote builder (no local Docker needed), returns the public *.fly.dev URL.

import fs from 'node:fs/promises'
import path from 'node:path'
import { spawn } from 'node:child_process'
import crypto from 'node:crypto'

const FLYCTL = process.env.FLYCTL_BIN || `${process.env.HOME}/.fly/bin/flyctl`

function run(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: opts.quiet ? 'pipe' : 'inherit', ...opts })
    let out = ''
    if (opts.quiet) {
      p.stdout?.on('data', d => out += d)
      p.stderr?.on('data', d => out += d)
    }
    p.on('exit', code => code === 0 ? resolve(out) : reject(new Error(`${cmd} ${args.join(' ')} exit ${code}\n${out}`)))
  })
}

// Fly's machine-launch/smoke-check auth has been throwing transient token
// timeouts ("token validation error … context deadline exceeded"). Those are
// platform-side and clear on retry. Run the deploy captured, and retry on a
// recognised transient error; surface anything else immediately.
const FLY_TRANSIENT = /token validation error|context deadline exceeded|smoke checks .*failed|failed to (launch|get) VM|no verified tokens|failed to acquire lease|lease currently held|failed to get lease/i
async function runWithRetry(cmd, args, opts = {}, attempts = 4) {
  let last
  for (let i = 0; i < attempts; i++) {
    try { return await run(cmd, args, { ...opts, quiet: true }) }
    catch (e) {
      last = e
      if (i < attempts - 1 && FLY_TRANSIENT.test(e.message)) {
        console.log(`  [fly deploy] transient Fly error (attempt ${i + 1}/${attempts}) — retrying in 6s…`)
        await new Promise(r => setTimeout(r, 6000))
        continue
      }
      throw e
    }
  }
  throw last
}

async function copyTree(src, dest) {
  await fs.mkdir(dest, { recursive: true })
  const entries = await fs.readdir(src, { withFileTypes: true })
  for (const e of entries) {
    const s = path.join(src, e.name)
    const d = path.join(dest, e.name)
    if (e.isDirectory()) await copyTree(s, d)
    else await fs.copyFile(s, d)
  }
}

export async function deployFly({ manifest, manifestPath, repoRoot, region = 'syd' }) {
  // Preflight: flyctl present + authed
  try { await run(FLYCTL, ['version'], { quiet: true }) } catch {
    throw new Error(`flyctl not found at ${FLYCTL}. Install: curl -L https://fly.io/install.sh | sh`)
  }
  try { await run(FLYCTL, ['auth', 'whoami'], { quiet: true }) } catch {
    throw new Error(`Not logged in to Fly. Run: ${FLYCTL} auth login`)
  }

  const classId = manifest.classId
  const hash = crypto.randomBytes(3).toString('hex')
  // Hostname derived from the per-deploy theme — NOT from the class ID — so the
  // URL doesn't telegraph the vulnerability class to a benchmark-aware model.
  const themeSlug = (manifest.theme?.siteName || 'site')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40) || 'site'
  const appName = `${themeSlug}-${hash}`.slice(0, 60)

  const classDir = path.join(repoRoot, 'classes', classId)
  const infraDir = path.join(classDir, 'infra')

  // Build context — Fly will tar this up and ship to the remote builder
  const buildDir = path.join('/tmp', `polyrange-fly-${hash}`)
  await fs.rm(buildDir, { recursive: true, force: true })
  await fs.mkdir(buildDir, { recursive: true })

  console.log(`  [build context] ${buildDir}`)

  // Copy infra files (Dockerfile etc) to build root — except package.json,
  // which we copy separately below to make the dep-isolation explicit.
  for (const f of await fs.readdir(infraDir)) {
    if (f === 'package.json') continue
    await fs.copyFile(path.join(infraDir, f), path.join(buildDir, f))
  }

  // Per-variant Dockerfile selection (e.g. polyglot SQL: sqlite/postgres/mysql
  // each need a different base image). If the class set manifest.infraVariant
  // and a Dockerfile.<variant> was copied in, use it as the build Dockerfile.
  if (manifest.infraVariant) {
    const vf = path.join(buildDir, `Dockerfile.${manifest.infraVariant}`)
    if (await fs.access(vf).then(() => true).catch(() => false)) {
      await fs.copyFile(vf, path.join(buildDir, 'Dockerfile'))
      console.log(`  [infra] using Dockerfile.${manifest.infraVariant}`)
    }
  }

  // Copy runtime + classes + package files
  await copyTree(path.join(repoRoot, 'runtime'), path.join(buildDir, 'runtime'))
  await fs.mkdir(path.join(buildDir, 'classes'), { recursive: true })
  await copyTree(path.join(repoRoot, 'classes', '_shared'), path.join(buildDir, 'classes', '_shared'))
  await copyTree(classDir, path.join(buildDir, 'classes', classId))
  await fs.rm(path.join(buildDir, 'classes', classId, 'infra'), { recursive: true, force: true })

  // Use the CLASS's own infra/package.json — XSS gets just zod, IDOR/SQLi
  // also get pg, etc. Top-level package.json is for dev tooling, not for
  // runtime containers.
  await fs.copyFile(path.join(infraDir, 'package.json'), path.join(buildDir, 'package.json'))

  // Bake the per-deploy manifest
  await fs.copyFile(manifestPath, path.join(buildDir, 'manifest.json'))

  // Generate fly.toml
  const flyToml = `app = "${appName}"
primary_region = "${region}"

[build]
  dockerfile = "Dockerfile"

[env]
  PORT = "8080"
  NODE_ENV = "production"

[http_service]
  internal_port = 8080
  force_https = true
  # Do not auto-stop: the runtime deletes the baked manifest from disk after
  # boot (anti-metadata-leakage), so an idle restart would re-read a now-missing
  # file. Targets are ephemeral / harness-managed, so a running machine has no
  # cost downside here.
  auto_stop_machines = false
  auto_start_machines = false
  min_machines_running = 1

[[vm]]
  size = "shared-cpu-1x"
  memory = "256mb"
`
  await fs.writeFile(path.join(buildDir, 'fly.toml'), flyToml)

  // Create the app
  console.log(`  [fly apps create] ${appName}`)
  await run(FLYCTL, ['apps', 'create', appName, '--org', 'personal'])

  // Deploy via remote builder.
  // --ha=false → single machine. Each machine has its own postgres-in-container,
  // so HA would split per-session DB state (signup on machine A invisible to a
  // request routed to machine B). Benchmark targets must be single-machine for
  // consistent runtime state.
  console.log(`  [fly deploy] remote-only, single machine (--ha=false)`)
  await runWithRetry(FLYCTL, ['deploy', '--remote-only', '--ha=false', '--app', appName, '--config', path.join(buildDir, 'fly.toml')], {
    cwd: buildDir,
  })

  const url = `https://${appName}.fly.dev`

  return {
    target: 'fly',
    url,
    appName,
    region,
    buildDir,
  }
}

export async function tearDownFly({ appName }) {
  await run(FLYCTL, ['apps', 'destroy', appName, '--yes'], { quiet: true }).catch(() => {})
}
