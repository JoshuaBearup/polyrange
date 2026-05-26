// Claude API wrapper. Production would call Cloudflare Workers AI.

const API_KEY = process.env.ANTHROPIC_API_KEY
if (!API_KEY) {
  console.error('ANTHROPIC_API_KEY env var not set')
  process.exit(1)
}

// Default to Haiku for speed; can be overridden per-call for the harder steps
const DEFAULT_MODEL = process.env.POLYRANGE_MODEL || 'claude-haiku-4-5-20251001'
const QUALITY_MODEL = 'claude-opus-4-7'

// ── Token accounting ────────────────────────────────────────────────────
// Every call records its usage so a deploy can report tokens + estimated $.
// PRICING is USD per 1M tokens — ESTIMATES; adjust to your actual contract.
const PRICING = {
  'claude-opus-4-7':           { in: 15, out: 75 },
  'claude-haiku-4-5-20251001': { in: 1,  out: 5  },
  'claude-sonnet-4-6':         { in: 3,  out: 15 },
}
let USAGE = []
export function resetUsage() { USAGE = [] }
export function getUsageReport() {
  const byModel = {}
  let inTok = 0, outTok = 0, cost = 0
  for (const u of USAGE) {
    const billedIn = u.input + u.cacheRead + u.cacheCreate
    inTok += billedIn; outTok += u.output
    const p = PRICING[u.model] || { in: 0, out: 0 }
    const c = (billedIn * p.in + u.output * p.out) / 1e6
    cost += c
    const m = (byModel[u.model] ||= { calls: 0, in: 0, out: 0, cost: 0 })
    m.calls++; m.in += billedIn; m.out += u.output; m.cost += c
  }
  return { calls: USAGE.length, inputTokens: inTok, outputTokens: outTok, totalTokens: inTok + outTok, estCostUsd: cost, byModel }
}

export async function callLLM({ system, user, maxTokens = 4096, expectJson = false, quality = false }) {
  const body = {
    model: quality ? QUALITY_MODEL : DEFAULT_MODEL,
    max_tokens: maxTokens,
    system,
    messages: [{ role: 'user', content: user }],
  }
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': API_KEY,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(`LLM call failed: ${res.status} ${txt}`)
  }
  const json = await res.json()
  const u = json.usage || {}
  USAGE.push({
    model: body.model,
    input: u.input_tokens || 0,
    output: u.output_tokens || 0,
    cacheRead: u.cache_read_input_tokens || 0,
    cacheCreate: u.cache_creation_input_tokens || 0,
  })
  const text = json.content?.[0]?.text ?? ''

  // Centralised: strip ANY markdown code-fence wrapping the LLM might have
  // added despite system-prompt instructions otherwise. This applies to every
  // call so individual generators can't forget to do it themselves.
  const cleaned = stripCodeFences(text)

  if (expectJson) {
    try { return JSON.parse(cleaned) }
    catch { throw new Error(`LLM returned non-JSON: ${text.slice(0, 500)}`) }
  }
  return cleaned
}

// Strip optional leading/trailing markdown code fences (```html, ```json, ```)
// from LLM responses. Robust to the LLM throwing them in even when told not to.
function stripCodeFences(text) {
  let t = text.trim()
  // Leading fence: ```<optional-lang>\n
  t = t.replace(/^```[a-zA-Z0-9_-]*\s*\n?/, '')
  // Trailing fence: \n```
  t = t.replace(/\n?\s*```\s*$/, '')
  return t.trim()
}
