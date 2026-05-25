// Tier 1 (signature WAF) demo server.
// Reads manifest.json. Applies WAF middleware. Blocks return Cloudflare 1020.

import http from 'node:http'
import fs from 'node:fs/promises'
import { URL } from 'node:url'

import { classDef } from './class.mjs'
import { tier1Middleware } from './defences-tier1.mjs'

const PORT = 7892
const HOST_URL = `http://127.0.0.1:${PORT}`

const manifest = JSON.parse(await fs.readFile('manifest.json', 'utf-8'))
const HOST_NAME = manifest.theme.domain || 'example.com'

function renderPage({ title, body }) {
  return manifest.chrome.replace('{BODY}', body)
}

const server = http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url, HOST_URL)
  const path = reqUrl.pathname

  // 0. WAF middleware first
  const blocked = await tier1Middleware(req, reqUrl, HOST_NAME)
  if (blocked) {
    res.writeHead(blocked.status, blocked.headers)
    res.end(blocked.body)
    return
  }

  // 1. Scenario endpoint
  if (path === manifest.scenario.endpoint.path && req.method === manifest.scenario.endpoint.method) {
    const binding = manifest.scenario.slots.user_input
    let userInput = ''
    if (binding.location === 'query') {
      userInput = reqUrl.searchParams.get(binding.name) ?? ''
    } else if (binding.location === 'body-form') {
      const body = req._consumedBody ?? ''
      userInput = new URLSearchParams(body).get(binding.name) ?? ''
    } else if (binding.location === 'body-json') {
      const body = req._consumedBody ?? ''
      try { userInput = JSON.parse(body)[binding.name] ?? '' } catch { userInput = '' }
    } else if (binding.location === 'header') {
      userInput = req.headers[binding.name.toLowerCase()] ?? ''
    }
    const scenarioInner = manifest.scenario.body.replaceAll('{INPUT}', userInput)
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    res.end(renderPage({ title: 'Search', body: scenarioInner }))
    return
  }

  // 2. Decoys
  if (manifest.decoys[path]) {
    const { title, body } = manifest.decoys[path]
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    res.end(renderPage({ title, body }))
    return
  }

  // 3. 404
  res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' })
  res.end(renderPage(manifest.fallback404))
})

server.listen(PORT, '127.0.0.1', () => {
  console.log(`\nTier 1 (signature WAF) — ${manifest.theme.siteName} — at ${HOST_URL}`)
  console.log(`  Naive XSS:   ${HOST_URL}${manifest.scenario.endpoint.path}?${manifest.scenario.slots.user_input.name}=<svg+onload=alert(1)>  (Cloudflare 1020)`)
  console.log(`  Bypass try:  ${HOST_URL}${manifest.scenario.endpoint.path}?${manifest.scenario.slots.user_input.name}=<details+open+ontoggle=alert(1)>`)
  console.log(`\nCtrl+C to stop.\n`)
})
