// Multi-class server. Loads a manifest, parses scenario through the class's
// Zod schema at startup (loud failure if mismatched), dispatches per class.

import http from 'node:http'
import fs from 'node:fs/promises'
import path from 'node:path'
import { URL } from 'node:url'

const args = Object.fromEntries(
  process.argv.slice(2).map(a => {
    const [k, v] = a.replace(/^--/, '').split('=')
    return [k, v ?? true]
  })
)
const manifestPath = args.manifest || 'manifest.wstg-xss-4.7.1.json'
const PORT = parseInt(args.port || '7895', 10)
const HOST_URL = `http://127.0.0.1:${PORT}`

const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf-8'))
const { classDef } = await import(path.resolve(`./classes/${manifest.classId}/behaviour.mjs`))

// Parse the scenario through the schema NOW (at startup) — fail loud if
// manifest is incompatible with the class schema. Avoids silent runtime drift.
let scenario
try {
  scenario = classDef.Scenario.parse(manifest.scenario)
} catch (err) {
  console.error(`✗ Manifest scenario does not validate against ${manifest.classId} schema:`)
  console.error(err.issues?.map(i => `  - ${i.path.join('.')}: ${i.message}`).join('\n') || err.message)
  process.exit(1)
}

function renderPage(body) {
  return manifest.chrome.replace('{BODY}', body)
}

function ensureSession(req, res) {
  const cookies = (req.headers.cookie ?? '').split(';').map(s => s.trim())
  const existing = cookies.find(c => c.startsWith('session='))
  if (existing) return existing.split('=')[1]
  // For IDOR: auto-set the default session
  if (manifest.classId === 'wstg-idor-4.5.4' && scenario.defaultSession) {
    res.setHeader('Set-Cookie', `session=${scenario.defaultSession}; Path=/; HttpOnly`)
    return scenario.defaultSession
  }
  return null
}

// ============================================================
// Per-class request handling — each branch references fields by the same
// names the schema defines.
// ============================================================
async function handleScenarioRequest(req, res, reqUrl) {
  const session = ensureSession(req, res)

  if (manifest.classId === 'wstg-xss-4.7.1') {
    const userInput = await extractInput(req, reqUrl, scenario.slots.user_input)
    const result = classDef.template({ rawScenario: scenario, userInput })
    return { status: result.status, body: renderPage(result.body) }
  }

  if (manifest.classId === 'wstg-idor-4.5.4') {
    const idLoc = scenario.endpoint.identifierLocation
    const idName = scenario.endpoint.identifierName
    let requestedId
    if (idLoc === 'path-segment') {
      const segs = reqUrl.pathname.split('/').filter(Boolean)
      requestedId = segs[segs.length - 1]
    } else if (idLoc === 'query') {
      requestedId = reqUrl.searchParams.get(idName)
    } else if (idLoc === 'body-json') {
      const chunks = []
      for await (const c of req) chunks.push(c)
      try { requestedId = JSON.parse(Buffer.concat(chunks).toString())[idName] } catch {}
    }
    const result = classDef.template({ rawScenario: scenario, requestedId, session })
    return { status: result.status, body: renderPage(result.body) }
  }

  if (manifest.classId === 'wstg-sqli-4.7.5.4') {
    const rawInput = await extractInput(req, reqUrl, scenario.slots.user_input)
    const result = classDef.template({ rawScenario: scenario, rawInput })
    return { status: result.status, body: renderPage(result.body) }
  }

  return { status: 500, body: 'Unknown class' }
}

async function extractInput(req, reqUrl, binding) {
  if (!binding) return ''
  if (binding.location === 'query') return reqUrl.searchParams.get(binding.name) ?? ''
  if (binding.location === 'header') return req.headers[binding.name.toLowerCase()] ?? ''
  if (binding.location === 'body-form' || binding.location === 'body-json') {
    const chunks = []
    for await (const c of req) chunks.push(c)
    const body = Buffer.concat(chunks).toString()
    if (binding.location === 'body-form') return new URLSearchParams(body).get(binding.name) ?? ''
    try { return JSON.parse(body)[binding.name] ?? '' } catch { return '' }
  }
  return ''
}

function matchesScenarioPath(reqUrl) {
  const epPath = scenario.endpoint.path
  if (reqUrl.pathname === epPath) return true
  if (epPath.includes(':') || epPath.includes('{')) {
    const pattern = new RegExp('^' + epPath.replace(/:\w+|\{\w+\}/g, '[^/]+') + '$')
    return pattern.test(reqUrl.pathname)
  }
  return false
}

const server = http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url, HOST_URL)

  try {
    if (matchesScenarioPath(reqUrl) && req.method === (scenario.endpoint.method || 'GET')) {
      ensureSession(req, res)
      const result = await handleScenarioRequest(req, res, reqUrl)
      res.writeHead(result.status, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(result.body)
      return
    }

    if (manifest.decoys[reqUrl.pathname]) {
      ensureSession(req, res)
      const { body } = manifest.decoys[reqUrl.pathname]
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(renderPage(body))
      return
    }

    res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' })
    res.end(renderPage(manifest.fallback404.body))
  } catch (err) {
    console.error('handler error:', err)
    res.writeHead(500, { 'Content-Type': 'text/plain' })
    res.end('Server error')
  }
})

server.listen(PORT, '127.0.0.1', () => {
  console.log(`\n${manifest.theme.siteName} (${manifest.classId}) at ${HOST_URL}`)
  console.log(`  scenario: ${scenario.endpoint.method || 'GET'} ${scenario.endpoint.path}`)
  console.log(`  canary:   ${manifest.perDeployCanary}`)
  if (manifest.classId === 'wstg-idor-4.5.4') {
    const canary = scenario.principalRecords?.find(r => r.isCanaryRecord)
    if (canary) console.log(`  IDOR target: identifier = ${canary.identifier}`)
  }
  if (manifest.classId === 'wstg-sqli-4.7.5.4') {
    console.log(`  SQLi: try input like \"' UNION SELECT * FROM ${scenario.sensitiveTable} --\"`)
  }
  console.log(`\nCtrl+C to stop.\n`)
})
