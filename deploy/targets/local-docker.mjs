// Local Docker deployer.
// Given a generated manifest, packages it with the class's infra template
// into a temp build directory, builds the image, and runs the container.

import fs from 'node:fs/promises'
import path from 'node:path'
import { spawn } from 'node:child_process'
import crypto from 'node:crypto'

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

export async function deployLocalDocker({ manifest, manifestPath, repoRoot }) {
  const classId = manifest.classId
  const hash = crypto.randomBytes(3).toString('hex')
  const tag = `polyrange-${classId.replace(/\./g, '-')}-${hash}`
  const containerName = tag

  const classDir = path.join(repoRoot, 'classes', classId)
  const infraDir = path.join(classDir, 'infra')

  // Build context — temp dir we copy everything the Dockerfile needs into
  const buildDir = path.join('/tmp', `polyrange-build-${hash}`)
  await fs.rm(buildDir, { recursive: true, force: true })
  await fs.mkdir(buildDir, { recursive: true })

  console.log(`  [build context] ${buildDir}`)

  // Copy infra files to build root (Dockerfile lives at build root) — except
  // package.json, which we copy separately below to make dep-isolation explicit.
  for (const f of await fs.readdir(infraDir)) {
    if (f === 'package.json') continue
    await fs.copyFile(path.join(infraDir, f), path.join(buildDir, f))
  }

  // Per-variant Dockerfile selection. Mirrors the fly target so polyglot /
  // multi-variant classes build the right image locally too.
  if (manifest.infraVariant) {
    const vf = path.join(buildDir, `Dockerfile.${manifest.infraVariant}`)
    if (await fs.access(vf).then(() => true).catch(() => false)) {
      await fs.copyFile(vf, path.join(buildDir, 'Dockerfile'))
      console.log(`  [infra] using Dockerfile.${manifest.infraVariant}`)
    }
  }

  // Copy runtime + classes + package files (the Dockerfile references them)
  await copyTree(path.join(repoRoot, 'runtime'), path.join(buildDir, 'runtime'))
  await fs.mkdir(path.join(buildDir, 'classes'), { recursive: true })
  await copyTree(path.join(repoRoot, 'classes', '_shared'), path.join(buildDir, 'classes', '_shared'))
  await copyTree(classDir, path.join(buildDir, 'classes', classId))
  // Don't ship the infra folder inside the image
  await fs.rm(path.join(buildDir, 'classes', classId, 'infra'), { recursive: true, force: true })

  // Use the CLASS's own infra/package.json — runtime deps per class
  await fs.copyFile(path.join(infraDir, 'package.json'), path.join(buildDir, 'package.json'))

  // Bake the per-deploy manifest into the image as manifest.json
  await fs.copyFile(manifestPath, path.join(buildDir, 'manifest.json'))

  // Build image
  console.log(`  [docker build] ${tag}`)
  await run('docker', ['build', '-t', tag, buildDir])

  // Tear down any old container with the same name (idempotency for re-deploys)
  await run('docker', ['rm', '-f', containerName], { quiet: true }).catch(() => {})

  // Pick a free local port
  const port = 8000 + Math.floor(Math.random() * 1000)

  // Run detached
  console.log(`  [docker run] ${containerName} on :${port}`)
  await run('docker', ['run', '-d', '--name', containerName, '-p', `${port}:8080`, tag])

  // Wait for container to be healthy
  await new Promise(r => setTimeout(r, 800))

  const url = `http://127.0.0.1:${port}`

  return {
    target: 'local-docker',
    url,
    containerName,
    imageTag: tag,
    port,
  }
}

export async function tearDownLocalDocker({ containerName }) {
  await run('docker', ['rm', '-f', containerName], { quiet: true }).catch(() => {})
}
