// End-to-end local test of the PolyRange architecture for reflected XSS.
//
// Steps:
//   1. Load class definition + scenario (simulating generator output)
//   2. Spin up a local HTTP server that hosts the parametric template +
//      scenario as a deployed challenge
//   3. Self-validate: run the canonical exploit against the server, check
//      the exploit success criterion fires
//   4. Report
//
// Run:  node run.mjs

import http from 'node:http'
import { URL } from 'node:url'

import { classDef } from './class.mjs'
import { canonicalExploit } from './canonical-exploit.mjs'
import { scenario } from './scenario.mjs'

const PORT = 7891
const HOST = `http://127.0.0.1:${PORT}`

// ============================================================
// 1. Realism validation (simplified for the local test)
// ============================================================
function validateRealism(scenario) {
  const issues = []
  const synthRegex = /(_[0-9a-f]{4,}|_[A-Z]{3,}_|test_|demo_|polyrange|benchmark)/i
  if (synthRegex.test(scenario.endpoint.path)) issues.push('endpoint.path looks synthetic')
  if (synthRegex.test(scenario.slots.user_input.name)) issues.push('user_input.name looks synthetic')
  if (!scenario.responseTemplate.includes('{INPUT}')) issues.push('responseTemplate missing {INPUT}')
  return { ok: issues.length === 0, issues }
}

// ============================================================
// 2. Deploy locally (start HTTP server hosting the scenario)
// ============================================================
function startServer() {
  return new Promise((resolve) => {
    const server = http.createServer(async (req, res) => {
      const reqUrl = new URL(req.url, HOST)

      // Only handle requests to the scenario's endpoint
      if (reqUrl.pathname !== scenario.endpoint.path) {
        res.writeHead(404)
        res.end('Not found')
        return
      }
      if (req.method !== scenario.endpoint.method) {
        res.writeHead(405)
        res.end('Method not allowed')
        return
      }

      // Extract the slot value based on the slot's location
      const binding = scenario.slots.user_input
      let userInput = ''
      if (binding.location === 'query') {
        userInput = reqUrl.searchParams.get(binding.name) ?? ''
      } else if (binding.location === 'body-form' || binding.location === 'body-json') {
        const chunks = []
        for await (const c of req) chunks.push(c)
        const body = Buffer.concat(chunks).toString()
        if (binding.location === 'body-form') {
          userInput = new URLSearchParams(body).get(binding.name) ?? ''
        } else {
          try { userInput = JSON.parse(body)[binding.name] ?? '' } catch { userInput = '' }
        }
      } else if (binding.location === 'header') {
        userInput = req.headers[binding.name.toLowerCase()] ?? ''
      }

      // Apply parametric template
      const result = classDef.template({
        slots: { user_input: userInput },
        scenario,
      })

      res.writeHead(result.status, result.headers)
      res.end(result.body)
    })

    server.listen(PORT, '127.0.0.1', () => resolve(server))
  })
}

// ============================================================
// 3. Self-validate exploitability
// ============================================================
async function selfValidate() {
  const results = []
  for (const payload of canonicalExploit.payloads) {
    const resp = await canonicalExploit.deliver(HOST, scenario, payload)
    const responseBody = await resp.text()
    const fired = classDef.exploitSuccessCriterion({
      responseBody,
      canary: canonicalExploit.canary,
    })
    results.push({
      payload: payload.length > 60 ? payload.slice(0, 60) + '...' : payload,
      status: resp.status,
      fired,
    })
    if (fired) break  // One success is enough
  }
  return results
}

// ============================================================
// Main
// ============================================================
async function main() {
  console.log('===========================================================')
  console.log('PolyRange — local end-to-end test')
  console.log('Class: WSTG-INPV-01 Reflected XSS')
  console.log('===========================================================\n')

  console.log('Step 1: Realism validation')
  const realism = validateRealism(scenario)
  console.log(realism.ok
    ? '  ✓ scenario passes realism check'
    : '  ✗ realism issues: ' + realism.issues.join(', '))
  if (!realism.ok) process.exit(1)

  console.log('\nStep 2: Deploy scenario locally')
  console.log(`  Feature: ${scenario.featureLabel}`)
  console.log(`  Endpoint: ${scenario.endpoint.method} ${scenario.endpoint.path}`)
  console.log(`  Slot binding: user_input → ${scenario.slots.user_input.location}.${scenario.slots.user_input.name}`)
  const server = await startServer()
  console.log(`  ✓ deployed at ${HOST}`)

  console.log('\nStep 3: Self-validate exploitability')
  const results = await selfValidate()
  for (const r of results) {
    console.log(`  ${r.fired ? '✓' : '✗'} [${r.status}] ${r.payload}`)
  }
  const exploitable = results.some((r) => r.fired)

  console.log('\n===========================================================')
  if (exploitable) {
    console.log('✓ SELF-VALIDATION PASSED — scenario is exploitable')
    console.log('  This scenario would be cleared for deployment to evaluators.')
  } else {
    console.log('✗ SELF-VALIDATION FAILED — scenario is not exploitable')
    console.log('  Generator would be asked to regenerate.')
  }
  console.log('===========================================================\n')

  // Also show what the deployed page actually looks like to a model
  console.log('Sample response to a benign request (what a model first sees):')
  const benign = await fetch(`${HOST}${scenario.endpoint.path}?q=laptop`)
  const benignBody = await benign.text()
  console.log('---')
  console.log(benignBody.split('\n').slice(0, 12).join('\n'))
  console.log('  ...\n')

  console.log('Sample response when canonical exploit fires:')
  const exploitResp = await canonicalExploit.deliver(HOST, scenario, canonicalExploit.payloads[0])
  const exploitBody = await exploitResp.text()
  console.log('---')
  console.log(exploitBody.split('\n').slice(0, 14).join('\n'))
  console.log('  ...\n')

  server.close()
  process.exit(exploitable ? 0 : 1)
}

main().catch((err) => {
  console.error('FATAL:', err)
  process.exit(2)
})
