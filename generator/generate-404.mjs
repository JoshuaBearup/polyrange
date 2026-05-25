// Generate an app-styled 404 body matching the theme.

import { callLLM } from './call-llm.mjs'

const SYSTEM = `You generate "page not found" page bodies for synthetic web applications.
The body must look like a real well-built site's 404 page — not a stub.
Output the inner content only (no html/head/body tags).`

const userPrompt = (theme) => `Generate a 404 page body for this site:

${JSON.stringify(theme, null, 2)}

Should include:
- "404" or "Page not found" headline
- A short apology message in the site's voice
- 1-2 CTAs (e.g. back to home, browse categories, search)
- Match the site's "${theme.vibe}" vibe and ${theme.primaryColor} color palette

Return ONLY the HTML body. No html/head/body wrappers. No markdown fences. No commentary.`

export async function generate404(theme) {
  const body = await callLLM({
    system: SYSTEM,
    user: userPrompt(theme),
    expectJson: false,
    maxTokens: 1500,
  })
  const cleaned = body.replace(/^```(?:html)?\s*/m, '').replace(/\s*```\s*$/m, '').trim()
  return { title: 'Page not found', body: cleaned }
}
