// Re-validation sweep: deploy every class through the HARDENED gates
// (slot-aware WAF, {BODY} chrome gate, browser oracle for client-side,
// anti-DVWA negative control, discovery) and record PASS/FAIL.
//
// Each deploy is --ephemeral: on success it self-destructs (account stays
// clean); on FAILURE it stays up so the broken target can be inspected.
//
// Driven from Node (sequential spawn) — the bash for-loop mangled iterations.
// Run: ANTHROPIC_API_KEY=... node scripts/revalidate-sweep.mjs

import { spawn } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const LOGDIR = '/tmp/pr-sweep'
fs.mkdirSync(LOGDIR, { recursive: true })

const SKIP = new Set(['wstg-search-recon-4.1.1']) // stale / out-of-scope

const classes = fs.readdirSync(path.join(ROOT, 'classes'))
  .filter(d => d.startsWith('wstg-') && !SKIP.has(d))
  .map(d => ({
    cls: d,
    tier: fs.existsSync(path.join(ROOT, 'classes', d, 'defences.mjs')) ? 1 : 0,
  }))
  .sort((a, b) => a.cls.localeCompare(b.cls))

function deployOne({ cls, tier }) {
  return new Promise((resolve) => {
    const p = spawn('node', ['generator/deploy.mjs', `--class=${cls}`, `--tier=${tier}`, '--target=fly', '--ephemeral'],
      { cwd: ROOT, env: process.env })
    let out = ''
    p.stdout.on('data', d => (out += d))
    p.stderr.on('data', d => (out += d))
    p.on('exit', (code) => {
      const validated = /VALIDATED at T/.test(out)
      const url = (out.match(/URL:\s*(\S+)/) || [])[1] || ''
      const failLine = (out.match(/✗[^\n]*/g) || []).slice(-1)[0] || `exit ${code}`
      const tokens = parseInt((out.match(/Tokens:\s*([\d,]+)/) || [])[1]?.replace(/,/g, '') || '0', 10)
      const cost = parseFloat((out.match(/Est\. cost:\s*\$([\d.]+)/) || [])[1] || '0')
      const secs = parseFloat((out.match(/Deploy complete in ([\d.]+)s/) || [])[1] || '0')
      fs.writeFileSync(path.join(LOGDIR, `${cls}.log`), out)
      resolve({ cls, tier, validated, url, failLine, tokens, cost, secs })
    })
  })
}

console.log(`Re-validation sweep — ${classes.length} classes (ephemeral)\n`)
const results = []
for (const c of classes) {
  process.stdout.write(`[${results.length + 1}/${classes.length}] ${c.cls} T${c.tier} ... `)
  const r = await deployOne(c)
  console.log(r.validated ? `PASS` : `FAIL — ${r.failLine.slice(0, 90)}`)
  results.push(r)
}

const pass = results.filter(r => r.validated)
const fail = results.filter(r => !r.validated)
const totTokens = results.reduce((s, r) => s + (r.tokens || 0), 0)
const totCost = results.reduce((s, r) => s + (r.cost || 0), 0)
const totSecs = results.reduce((s, r) => s + (r.secs || 0), 0)
console.log(`\n══════════════ SWEEP SUMMARY ══════════════`)
console.log(`PASS ${pass.length}/${results.length}`)
for (const r of fail) console.log(`  FAIL  ${r.cls} (T${r.tier}) — ${r.failLine.slice(0, 90)}  [log: ${LOGDIR}/${r.cls}.log]`)
if (fail.length) console.log(`\nFailed targets left UP for inspection. Logs in ${LOGDIR}/`)
console.log(`\nTokens: ${totTokens.toLocaleString()} total · Est. cost: $${totCost.toFixed(2)} · wall: ${(totSecs / 60).toFixed(1)}m`)
console.log(`Avg/deploy: ${Math.round(totTokens / results.length).toLocaleString()} tokens · $${(totCost / results.length).toFixed(3)}`)
fs.writeFileSync(path.join(LOGDIR, '_summary.json'), JSON.stringify(results, null, 2))
