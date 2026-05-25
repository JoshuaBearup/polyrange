// Claude API wrapper. Production would call Cloudflare Workers AI.

const API_KEY = process.env.ANTHROPIC_API_KEY
if (!API_KEY) {
  console.error('ANTHROPIC_API_KEY env var not set')
  process.exit(1)
}

// Default to Haiku for speed; can be overridden per-call for the harder steps
const DEFAULT_MODEL = process.env.POLYRANGE_MODEL || 'claude-haiku-4-5-20251001'
const QUALITY_MODEL = 'claude-opus-4-7'

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
  const text = json.content?.[0]?.text ?? ''
  if (expectJson) {
    const cleaned = text.replace(/^```(?:json)?\s*/m, '').replace(/\s*```\s*$/m, '').trim()
    try { return JSON.parse(cleaned) }
    catch { throw new Error(`LLM returned non-JSON: ${text.slice(0, 500)}`) }
  }
  return text
}
