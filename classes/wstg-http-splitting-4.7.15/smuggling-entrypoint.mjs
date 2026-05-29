// PolyRange — WSTG-INPV-15 smuggling-half entrypoint.
//
// Boots the raw-net Node backend on 127.0.0.1:$BACKEND_PORT (default 3000)
// behind an HAProxy frontend on :8080 (started by start.sh). Reads the
// per-deploy manifest, validates the scenario, then hands off to
// classDef.runSmugglingBackend.
//
// This entrypoint REPLACES runtime/server.mjs for the smuggling variant —
// the standard runtime parses HTTP via Node's http module, which would
// normalise CL/TE conflicts on its own and erase the desync. The raw-net
// backend honours Content-Length verbatim, which is the CL side of the
// CL.TE primitive.

import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { classDef, runSmugglingBackend } from './behaviour.mjs'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const MANIFEST_PATH = process.env.POLYRANGE_MANIFEST || path.resolve(__dirname, '..', '..', 'manifest.json')
const BACKEND_PORT = parseInt(process.env.BACKEND_PORT || '3000', 10)

const manifest = JSON.parse(await fs.readFile(MANIFEST_PATH, 'utf-8'))

// Match runtime/server.mjs: remove the manifest from disk after loading.
// HAProxy and the backend run in the same container; both keep the
// manifest in memory only.
await fs.unlink(MANIFEST_PATH).catch(() => {})

let scenario
try {
  scenario = classDef.Scenario.parse(manifest.scenario)
} catch (err) {
  console.error('Manifest scenario does not validate against schema:')
  console.error(err.issues?.map(i => `  - ${i.path.join('.')}: ${i.message}`).join('\n') || err.message)
  process.exit(1)
}

console.log(`[smuggling-backend] starting on 127.0.0.1:${BACKEND_PORT}`)
console.log(`[smuggling-backend] admin canary path: ${scenario.adminCanaryPath}`)
console.log(`[smuggling-backend] trusted-upstream header: ${scenario.trustedUpstreamHeader}: ${scenario.trustedUpstreamValue}`)

await runSmugglingBackend({
  scenario,
  canary: manifest.perDeployCanary,
  port: BACKEND_PORT,
})

console.log('[smuggling-backend] listening')
