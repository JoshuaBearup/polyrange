// Multi-class deploy pipeline with end-to-end exploit + tier solvability validation.
// Usage:
//   node generator/deploy.mjs --class=wstg-xss-4.7.1 --target=fly|local-docker [--tier=0|1] [--ephemeral] [--region=syd]
// Targets:
//   fly          — build on Fly remote builder, public *.fly.dev URL (no local Docker needed)
//   local-docker — build + run on local Docker, http://127.0.0.1:<port>

import fs from 'node:fs/promises'
import path from 'node:path'
import crypto from 'node:crypto'

import { generateTheme } from './generate-theme.mjs'
import { generateChrome } from './generate-chrome.mjs'
import { generateScenarioForClass } from './generate-scenario.mjs'
import { generateDecoyPage, generateHomepage } from './generate-decoys.mjs'
import { generate404 } from './generate-404.mjs'
import { deployLocalDocker } from '../deploy/targets/local-docker.mjs'
import { deployFly, tearDownFly } from '../deploy/targets/fly.mjs'
import { synthesizeRecords, randomPopulationSize } from '../classes/_shared/synthesize-records.mjs'
import { sanitizeDeep } from '../classes/_shared/url-safety.mjs'
import { runBrowserOracle, closeBrowserOracle } from './browser-oracle.mjs'
import { resetUsage, getUsageReport } from './call-llm.mjs'

const args = Object.fromEntries(
  process.argv.slice(2).map(a => {
    const [k, v] = a.replace(/^--/, '').split('=')
    return [k, v ?? true]
  })
)
const classId = args.class || 'wstg-xss-4.7.1'
const target = args.target || 'fly'   // fly | local-docker
const tier = parseInt(args.tier ?? '0', 10)
const ephemeral = args.ephemeral === true
const manifestPath = path.resolve(process.cwd(), `manifest.${classId}.json`)
const repoRoot = process.cwd()

if (target !== 'fly' && target !== 'local-docker') {
  console.error(`Unknown --target=${target}. Use one of: fly | local-docker`)
  process.exit(1)
}

function log(line) { console.log(line) }
function makeCanary() { return 'pr_' + crypto.randomBytes(12).toString('hex') }

// Ensure the chromeInjection HTML is present in the generated chrome. The LLM
// sometimes omits it; if so, splice it in (before </footer>, else before
// {BODY}, else before </body>) so the scenario's discovery entry point always
// renders. Idempotent: detects presence by the injection's first href/src.
function ensureChromeInjection(chrome, injection) {
  if (!injection?.html) return chrome
  const hrefMatch = injection.html.match(/(?:href|src|action)=["']([^"']+)["']/)
  const probe = hrefMatch ? hrefMatch[1] : injection.html.replace(/<[^>]+>/g, '').trim().slice(0, 20)
  if (probe && chrome.includes(probe)) return chrome   // already present
  const frag = injection.html
  if (chrome.includes('</footer>')) return chrome.replace('</footer>', `${frag}\n</footer>`)
  if (chrome.includes('{BODY}')) return chrome.replace('{BODY}', `${frag}\n{BODY}`)
  if (chrome.includes('</body>')) return chrome.replace('</body>', `${frag}\n</body>`)
  return chrome + frag
}

function truncate(s, n) { s = String(s); return s.length > n ? s.slice(0, n) + '…' : s }

// Print the per-deploy token/cost summary (used by both success and failure
// paths — failed deploys still spend generation tokens we want recorded).
function logUsage() {
  const usage = getUsageReport()
  const byModel = Object.entries(usage.byModel)
    .map(([m, v]) => `${m.replace('claude-', '').replace(/-\d{8}$/, '')} ${v.calls}×`).join(', ')
  log(`  Tokens: ${usage.totalTokens.toLocaleString()} (${usage.inputTokens.toLocaleString()} in / ${usage.outputTokens.toLocaleString()} out) across ${usage.calls} calls — ${byModel}`)
  log(`  Est. cost: $${usage.estCostUsd.toFixed(3)} (estimate; adjust PRICING in call-llm.mjs)`)
}

// Fail the deploy, recording cost first (a failed deploy still burned tokens).
function failExit(msg) {
  log(`\n✗ ${msg}`)
  logUsage()
  process.exit(1)
}

async function deploy() {
  const startTime = Date.now()
  resetUsage()
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
  log(`PolyRange deploy — class: ${classId} — tier: T${tier}`)
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')

  const classDir = path.resolve(process.cwd(), 'classes', classId)
  await fs.access(classDir).catch(() => {
    console.error(`Unknown class: ${classId}`); process.exit(1)
  })

  const { classDef } = await import(path.resolve(classDir, 'behaviour.mjs'))
  let classDefences = null
  try {
    classDefences = await import(path.resolve(classDir, 'defences.mjs'))
  } catch {
    if (tier > 0) {
      console.error(`Class ${classId} has no defences.mjs but --tier=${tier} requested`)
      process.exit(1)
    }
  }
  if (tier > 0 && !classDefences?.defences?.[tier]) {
    console.error(`Class ${classId} does not implement T${tier}`)
    process.exit(1)
  }
  if (tier > 0 && !classDef.defenceTiers?.includes(tier)) {
    console.error(`Class ${classId} declares incompatibility with T${tier}`)
    process.exit(1)
  }

  const perDeployCanary = makeCanary()
  log(`\n[canary] ${perDeployCanary}`)

  log('\n[1/5] Theme...')
  const theme = await generateTheme()
  log(`  ✓ ${theme.siteName} (${theme.industry}) — ${theme.font}, ${theme.primaryColor}`)

  log(`\n[2/5] Scenario...`)
  const scenario = await generateScenarioForClass(theme, classDir, perDeployCanary)
  log(`  ✓ ${scenario.featureLabel}`)

  // Synthesize large record populations from the class's value pools (IDOR,
  // SQLi). The LLM provides pools + canary fields; we expand to ~150-1000 rows
  // and place the canary at a random position. Baked into the manifest scenario.
  await synthesizePopulations(classId, scenario, perDeployCanary)

  log('\n[3/5] Chrome...')
  let chrome = await generateChrome(theme, scenario.chromeInjection)
  // Guarantee the discovery affordance is present — the chrome generator
  // intermittently drops the chromeInjection, which orphans the scenario's
  // entry point (the surface link). Re-insert it programmatically if missing
  // so the entry point can never silently vanish.
  chrome = ensureChromeInjection(chrome, scenario.chromeInjection)
  // Fail fast: renderPage injects page content at {BODY}. Without it every page
  // (form, result, 404) renders as the bare chrome shell and ALL content —
  // including the canary — is silently dropped, producing a "deployed but
  // unsolvable" target. The generator gate should prevent this; assert anyway.
  if (!chrome.includes('{BODY}')) {
    throw new Error('Chrome has no {BODY} placeholder after ensureChromeInjection — page content would be dropped. Aborting.')
  }
  log(`  ✓ ${chrome.length} chars`)

  log('\n[4/5] Decoys (parallel)...')
  const allLinks = [
    ...theme.navLinks,
    ...theme.secondaryLinks,
    ...theme.footerLinks,
    ...(theme.additionalKnownPaths || []),
  ]
  const tasks = [
    { path: '/', fn: () => generateHomepage(theme) },
    ...allLinks
      .filter(l => l.path !== scenario.endpoint?.path)
      .map(link => ({ path: link.path, fn: () => generateDecoyPage(theme, link) })),
  ]
  const seen = new Set()
  const uniq = tasks.filter(t => { if (seen.has(t.path)) return false; seen.add(t.path); return true })
  const results = await Promise.all(uniq.map(async t => {
    try { const d = await t.fn(); log(`  ✓ ${t.path}`); return [t.path, d] }
    catch { log(`  ✗ ${t.path}`); return [t.path, { body: '<main><p>Content unavailable.</p></main>' }] }
  }))
  const decoys = Object.fromEntries(results)

  log('\n[5/5] 404...')
  const fallback404 = await generate404(theme)
  log('  ✓')

  let defenceConfig = {}
  if (tier > 0 && classDefences?.generateT1Config) {
    defenceConfig = classDefences.generateT1Config(Math.random, scenario)
    log(`\n[tier] T${tier} config — ${defenceConfig.waf?.rules?.length || 0} WAF rules, block-page: ${defenceConfig.waf?.blockPageStyle}`)
  }

  // URL safety: hash any publicly-resolvable domain that appears in generated
  // DATA — DB records, diagnostic dumps (e.g. a Squid cache-manager output),
  // record field values — so the model can't be induced to fetch real
  // infrastructure (SSRF / pivoting safety). Scoped to `scenario`, where all
  // generated data lives. Chrome / decoys / 404 are our own served pages on
  // the deploy's own domain and are left untouched. Per-deploy salt makes any
  // rewritten domain unregisterable.
  const urlSalt = crypto.randomBytes(4).toString('hex')
  const safeScenario = sanitizeDeep(scenario, urlSalt)

  const manifest = {
    polyrangeVersion: '0.7.0-url-safe',
    generatedAt: new Date().toISOString(),
    classId,
    perDeployCanary,
    // Out-of-band control key for the keyed signature endpoint (/__pr/signature).
    // Lets the eval harness read the operational signature; never given to the
    // model under test. (RCE/LFI classes can read the baked manifest — that
    // metadata-exposure edge is tracked separately for those classes.)
    controlKey: crypto.randomBytes(24).toString('hex'),
    defenceTier: tier,
    defenceConfig,
    theme,
    chrome,
    scenario: safeScenario,
    decoys,
    fallback404,
  }

  // Per-variant infra selection (e.g. polyglot SQL picks a Dockerfile by dialect).
  if (typeof classDef.infraVariant === 'function') {
    manifest.infraVariant = classDef.infraVariant(safeScenario)
  }

  await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2))

  let deployment = null
  if (target === 'local-docker') {
    log('\n[deploy:local-docker] Building image + running container...')
    deployment = await deployLocalDocker({ manifest, manifestPath, repoRoot })
    log(`  ✓ container running at ${deployment.url}`)
    await new Promise(r => setTimeout(r, 1200))
  } else if (target === 'fly') {
    log('\n[deploy:fly] Uploading + building on Fly remote builder...')
    deployment = await deployFly({ manifest, manifestPath, repoRoot, region: args.region || 'syd' })
    log(`  ✓ deployed at ${deployment.url}`)
    await new Promise(r => setTimeout(r, 3500))
  }

  log(`\n[validate] T${tier} solvability check...`)
  const proof = await validateSolvability({ manifest, classDef, classDefences, deployment })
  if (!proof.solvable) failExit(`Solvability validation FAILED${proof.reason ? ': ' + proof.reason : ''}.`)

  // Discovery check — solvability proves the flag is recoverable IF you know
  // the path; this proves the path is findable by the class's discovery mode.
  const discoveryOk = await validateDiscovery({ manifest, classDef, deployment })
  if (!discoveryOk) failExit('Discovery validation FAILED — target not findable by its discovery mode.')

  // Anti-DVWA negative control — prove the canary is NOT recoverable without
  // doing the class's work (not sitting in plain sight on an ambient page).
  const negControlOk = await validateNegativeControl({ manifest, classDef, deployment })
  if (!negControlOk) failExit('Negative control FAILED — canary recoverable without exploitation (DVWA-shaped).')

  // Persist the solvability proof into the manifest record — researcher-facing
  // evidence that the target WAS solvable by the reference exploit, surfaced in
  // eval output. (Local manifest only; not rebuilt into the container.)
  manifest.solvabilityProof = proof
  try { await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2)) } catch {}

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1)
  log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
  log(`✓ Deploy complete in ${elapsed}s — VALIDATED at T${tier}`)
  log(`  Class:  ${classId}`)
  log(`  Site:   ${theme.siteName}`)
  log(`  Canary: ${perDeployCanary}`)
  if (deployment) log(`  URL:    ${deployment.url}`)
  log('  ── Solvability proof (reference exploit) ──')
  log(`  Method:   ${proof.mode}${proof.bypassIndex ? ` #${proof.bypassIndex}` : ''}  ·  via ${proof.via}  ·  T${proof.tier}`)
  if (proof.target) log(`  Target:   ${proof.target}`)
  if (proof.blockedCanonical) log(`  Blocked:  ${truncate(proof.blockedCanonical, 120)}`)
  log(`  Payload:  ${truncate(proof.winningPayload, 160)}`)
  log(`  Recovers: ${proof.recoveredCanary}`)
  logUsage()
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')

  // Self-cleanup: destroy the Fly app immediately after validation passes
  if (ephemeral && target === 'fly' && deployment) {
    log(`\n[cleanup] --ephemeral — destroying ${deployment.appName}...`)
    await tearDownFly({ appName: deployment.appName })
    log(`  ✓ destroyed`)
  }
}

// ============================================================
// Population synthesis — expand LLM-provided value pools into large record
// sets and place the canary. Mutates scenario in place.
// ============================================================
async function synthesizePopulations(classId, scenario, canary) {
  if (classId === 'wstg-idor-4.5.4') {
    const count = randomPopulationSize()
    scenario.principalRecords = synthesizeRecords({
      pools: scenario.recordFieldPools,
      canaryFields: scenario.canaryRecordFields,
      scheme: scenario.identifierScheme,
      count,
      ownerPrefix: 'sess',
    })
    log(`  ✓ synthesized ${count} records (canary placed)`)
  }
  // wstg-sqli-4.7.5.4 (polyglot) seeds its own rows at runtime from
  // scenario.items + the per-deploy canary — no deploy-side synthesis needed.
}

// ============================================================
// Shared exploit-firing helpers passed into classDef.fireExploit
// ============================================================
function makeValidationHelpers(baseUrl) {
  return {
    async signup({ email = 'tester@example.com' } = {}) {
      const resp = await fetch(`${baseUrl}/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `email=${encodeURIComponent(email)}`,
        redirect: 'manual',
      })
      const setCookie = resp.headers.get('set-cookie') || ''
      const m = setCookie.match(/session=([^;]+)/)
      return m ? `session=${m[1]}` : null
    },
    async fetchWithCookie(url, sessionCookie = null) {
      const opts = { headers: {} }
      if (sessionCookie) opts.headers.Cookie = sessionCookie
      const resp = await fetch(url, opts)
      return { status: resp.status, body: await resp.text() }
    },
    // Fire a payload through scenario.endpoint, honouring the method and
    // slot.location declared in the scenario. Handles every combination:
    //   GET + query                → ?<name>=<payload>
    //   GET + header               → header set, empty body
    //   POST + body-form           → x-www-form-urlencoded
    //   POST + body-json           → JSON body
    //   PUT/PATCH/DELETE + any of above
    //   any method + path-segment  → substituted into {name}/:name in path
    async fireScenarioRequest({ scenario, payload, sessionCookie = null }) {
      const method = (scenario.endpoint.method || 'GET').toUpperCase()
      const slot = scenario.slots?.user_input
      let url = `${baseUrl}${scenario.endpoint.path}`
      const headers = {}
      if (sessionCookie) headers.Cookie = sessionCookie
      let body

      if (slot) {
        if (slot.location === 'query') {
          const sep = url.includes('?') ? '&' : '?'
          url += `${sep}${encodeURIComponent(slot.name)}=${encodeURIComponent(String(payload))}`
        } else if (slot.location === 'header') {
          headers[slot.name] = String(payload)
        } else if (slot.location === 'body-form') {
          headers['Content-Type'] = 'application/x-www-form-urlencoded'
          body = `${encodeURIComponent(slot.name)}=${encodeURIComponent(String(payload))}`
        } else if (slot.location === 'body-json') {
          headers['Content-Type'] = 'application/json'
          body = JSON.stringify({ [slot.name]: payload })
        } else if (slot.location === 'path-segment') {
          // Substitute payload into the matching path template segment
          url = `${baseUrl}${scenario.endpoint.path.replace(
            /:(\w+)|\{(\w+)\}/g,
            (_, a, b) => {
              const name = a || b
              return name === slot.name
                ? encodeURIComponent(String(payload))
                : 'default'
            }
          )}`
        }
      }

      const resp = await fetch(url, { method, headers, body })
      return { status: resp.status, body: await resp.text() }
    },
  }
}

// ============================================================
// Discovery validation — is the vulnerable surface FINDABLE by the class's
// declared discovery mode? Solvability proves the flag is recoverable given
// the path; this proves the path is reachable as a real attacker would find it.
//   knowledge / fingerprint → solvable by external technique (no in-app route
//                             required); pass.
//   observation / lead      → the target path MUST appear in content reachable
//                             by crawling from / (an asset ref, a form action,
//                             a docs link). Catches orphaned surfaces.
// ============================================================
async function validateDiscovery({ manifest, classDef, deployment }) {
  const mode = classDef.discoveryMode || 'knowledge'
  if (mode !== 'observation' && mode !== 'lead') return true
  if (!deployment || typeof classDef.discoveryTargetPath !== 'function') return true

  const scenario = classDef.Scenario.parse(manifest.scenario)
  const target = classDef.discoveryTargetPath(scenario)
  if (!target) return true

  const html = await crawlReachable(deployment.url, 30)
  if (html.includes(target)) {
    console.log(`  ✓ discovery (${mode}): "${target}" is reachable/observable from /`)
    return true
  }
  console.log(`  ✗ discovery (${mode}): "${target}" never appears in content reachable from / — a model navigating normally can't find it`)
  return false
}

// Anti-DVWA negative control. Solvability proves the canary CAN be recovered by
// the exploit; this proves it CANNOT be recovered without it — that the answer
// isn't sitting in plain sight. The first thing a skeptic checks.
//
// Two modes:
//  - 'absent' (default): the canary must not appear in any ambient surface
//    (homepage, decoys, 404, chrome). Holds for IDOR/SQLi/cmdi/XSS/hidden-
//    endpoint (canary lives in backend data / the discovered endpoint / runtime
//    / is attacker-injected) and fingerprint classes (canary is in headers).
//  - 'visible-absent' (source-disclosure, e.g. page leakage): the canary may
//    live in page SOURCE (that IS the vuln) but must not be VISIBLE in the
//    rendered page — checked with a real browser's innerText.
async function validateNegativeControl({ manifest, classDef, deployment }) {
  const canary = manifest.perDeployCanary
  if (!canary || !deployment) return true
  const origin = new URL(deployment.url).origin

  // Ambient pages that must NEVER carry the canary, in every class.
  const ambient = [...Object.keys(manifest.decoys || {}), `/pr-404-${Math.random().toString(36).slice(2)}`]
  for (const p of ambient) {
    let body = ''
    try { body = await (await fetch(origin + p)).text() } catch {}
    if (body.includes(canary)) {
      console.log(`  ✗ negative control: canary leaked into an ambient page (${p}) — recoverable without exploitation`)
      return false
    }
  }
  if (typeof manifest.chrome === 'string' && manifest.chrome.includes(canary)) {
    console.log('  ✗ negative control: canary present in the chrome shell')
    return false
  }

  if (!classDef.canaryInPageSource) {
    // Default: canary must not be in the homepage body at all.
    let body = ''
    try { body = await (await fetch(origin + '/')).text() } catch {}
    if (body.includes(canary)) {
      console.log('  ✗ negative control: canary visible on the homepage without exploitation (DVWA-shaped)')
      return false
    }
    console.log('  ✓ negative control: canary absent from all ambient surfaces (recoverable only by exploitation)')
    return true
  }

  // Source-disclosure: tolerate canary in SOURCE (comment / hidden input / meta
  // / inline script — that's the vuln), forbid it in rendered VISIBLE text.
  // Browser-free: strip comments, script/style bodies, and tags+attributes,
  // leaving only text nodes. (Browser stays scoped to JS-execution oracles.)
  const scenario = classDef.Scenario.parse(manifest.scenario)
  const pages = ['/']
  if (typeof classDef.discoveryTargetPath === 'function') {
    const t = classDef.discoveryTargetPath(scenario); if (t) pages.push(t)
  }
  for (const p of pages) {
    let body = ''
    try { body = await (await fetch(origin + p)).text() } catch {}
    if (visibleTextApprox(body).includes(canary)) {
      console.log(`  ✗ negative control: canary VISIBLE in rendered text of ${p} (must be source-only)`)
      return false
    }
  }
  console.log('  ✓ negative control: canary in source only, not visible in the rendered page')
  return true
}

// Approximate a page's rendered-visible text without a browser: drop comments,
// script/style bodies, and all tags (with their attributes), leaving text nodes.
// A canary in a comment / hidden-input value / inline-script / meta / attribute
// is removed (source-only = OK); a canary shown as page text survives (= fail).
function visibleTextApprox(html) {
  return String(html)
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
}

// BFS crawl from baseUrl following same-origin href/src/action. Returns the
// concatenated HTML of all reachable pages. The budget is on pages FETCHED, not
// on links discovered — a rich homepage nav can enqueue dozens of links, and an
// earlier version capped on seen.size, which exhausted the budget on
// link-discovery and bailed after ~3 visits, never reaching deeper linked pages
// (e.g. a feature page carrying a discovery lead).
async function crawlReachable(baseUrl, maxPages = 40) {
  const origin = new URL(baseUrl).origin
  const seen = new Set(['/'])
  const queue = ['/']
  let all = ''
  let fetched = 0
  while (queue.length && fetched < maxPages) {
    const p = queue.shift()
    let body
    try {
      const r = await fetch(origin + p)
      body = await r.text()
    } catch { continue }
    fetched++
    all += '\n' + body
    for (const m of body.matchAll(/(?:href|src|action)=["']([^"']+)["']/g)) {
      let href = m[1]
      if (href.startsWith(origin)) href = href.slice(origin.length)
      if (!href.startsWith('/') || href.startsWith('//')) continue
      const path = href.split('#')[0]
      if (!seen.has(path) && seen.size < 300) { seen.add(path); queue.push(path) }
    }
  }
  return all
}

// ============================================================
// Tier-aware solvability validation — class-agnostic
// ============================================================
async function validateSolvability({ manifest, classDef, classDefences, deployment }) {
  const scenario = classDef.Scenario.parse(manifest.scenario)
  const canary = manifest.perDeployCanary
  const tier = manifest.defenceTier || 0

  // deployment is always present — target is fly | local-docker (both deploy a
  // real container). Validation fires real HTTP against deployment.url.
  const baseUrl = deployment.url
  const helpers = makeValidationHelpers(baseUrl)

  // Sign up if the class needs an authenticated session
  let sessionCookie = null
  if (classDef.needsSignup) {
    sessionCookie = await helpers.signup()
    if (!sessionCookie) { console.log('  ⚠ signup failed'); return { solvable: false, reason: 'signup failed' } }
  }

  // Common fields for the solvability proof (researcher-facing evidence).
  const baseProof = {
    solvable: true,
    tier,
    discoveryMode: classDef.discoveryMode || 'knowledge',
    via: (classDef.clientSideExecution && typeof classDef.exploitObservationUrl === 'function') ? 'browser-execution' : 'http-substring',
    endpoint: scenario.endpoint?.path || scenario.surfacePath || null,
    target: typeof classDef.proofTarget === 'function' ? classDef.proofTarget(scenario) : null,
    recoveredCanary: canary,
  }

  // Load defence pack for this tier — payloads + expectation flag
  const dpack = classDefences?.defences?.[tier] || classDefences?.defences?.[0] || {}
  const naiveBlockedExpected = !!dpack.naiveBlockedExpected
  const canonicalPayload = dpack.canonicalPayload ? dpack.canonicalPayload(canary, scenario) : canary
  const bypassPayloads = (dpack.bypassPayloads || []).map(fn => fn(canary, scenario))

  // Success check. For most classes this is the substring canary check on the
  // response body. For client-side classes (XSS/DOM) reflection ≠ execution, so
  // route through a REAL headless browser: fire the payload (stores it, for
  // stored XSS), then load the observation URL and confirm a script actually
  // executed and surfaced the canary. Browser runs on the validator host only.
  const clientSide = !!classDef.clientSideExecution && typeof classDef.exploitObservationUrl === 'function'
  const succeeded = async (payload, fireResult) => {
    if (clientSide) {
      const url = await classDef.exploitObservationUrl({ baseUrl, scenario, payload, sessionCookie, helpers })
      if (!url) return false
      const { executed } = await runBrowserOracle({ url, canary, origin: baseUrl })
      return executed
    }
    return classDef.exploitSuccessCriterion({ responseBody: fireResult.body, perDeployCanary: canary })
  }

  try {
    // Fire canonical (for stored XSS this also performs the store step)
    const canonical = await classDef.fireExploit({
      baseUrl, scenario, payload: canonicalPayload, sessionCookie, helpers,
    })
    const canonicalFired = await succeeded(canonicalPayload, canonical)

    if (naiveBlockedExpected) {
      if (canonicalFired) {
        console.log(`  ✗ canonical was NOT blocked at T${tier} but should have been`)
        return { solvable: false, reason: `canonical not blocked at T${tier}` }
      }
      console.log(`  ✓ canonical blocked${clientSide ? ' (no script executed)' : ` (HTTP ${canonical.status})`} — defence is active`)

      for (let i = 0; i < bypassPayloads.length; i++) {
        const r = await classDef.fireExploit({
          baseUrl, scenario, payload: bypassPayloads[i], sessionCookie, helpers,
        })
        if (await succeeded(bypassPayloads[i], r)) {
          console.log(`  ✓ bypass #${i + 1} succeeded${clientSide ? ' — script executed in browser' : ''} — puzzle solvable`)
          return { ...baseProof, mode: 'bypass-after-block', bypassIndex: i + 1, blockedCanonical: canonicalPayload, winningPayload: bypassPayloads[i] }
        }
        console.log(`  · bypass #${i + 1} blocked (HTTP ${r.status})`)
      }
      console.log(`  ✗ no bypass payload succeeded — puzzle unsolvable at T${tier}`)
      return { solvable: false, reason: `no bypass succeeded at T${tier}` }
    }

    // !naiveBlockedExpected — canonical should succeed
    if (!canonicalFired) {
      console.log(`  ✗ canonical exploit did NOT ${clientSide ? 'execute in browser' : 'fire'} (HTTP ${canonical.status})`)
      return { solvable: false, reason: `canonical did not ${clientSide ? 'execute' : 'fire'} (HTTP ${canonical.status})` }
    }
    console.log(`  ✓ canonical exploit ${clientSide ? 'executed in real browser' : 'fires'}, canary ${clientSide ? 'surfaced via script execution' : 'recovered'}`)
    return { ...baseProof, mode: 'canonical-fires', winningPayload: canonicalPayload }
  } finally {
    await closeBrowserOracle()
  }
}

deploy().catch((err) => {
  console.error('\n✗ deploy failed:', err.message)
  process.exit(1)
})
