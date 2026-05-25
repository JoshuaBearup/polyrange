// Generate a chrome template aware of the scenario.
// Takes theme + scenario.chromeInjection — bakes the discovery affordance
// into the chrome so the scenario endpoint is reachable from any page.

import { callLLM } from './call-llm.mjs'

const SYSTEM = `You generate HTML chrome templates for synthetic web applications.
The chrome is the page wrapper — DOCTYPE, head, header, nav, footer — into
which page bodies are slotted via a {BODY} placeholder.

You are also given a "chromeInjection" — a small HTML fragment that the
scenario needs you to include in a specific location (header-search,
header-end, footer, or nav-extra). This is how the scenario endpoint stays
discoverable through normal site navigation. INCLUDE IT — failing to include
it makes the scenario unreachable.

NEVER produce:
- The string "polyrange" or "benchmark" anywhere
- Placeholder names like "Acme" or "Example"
- Lorem ipsum or stub text in the chrome
- Broken or invented framework versions

ALWAYS produce:
- A coherent, working HTML structure
- The font specified by the theme, loaded from Google Fonts
- The cssApproach specified by the theme (Tailwind via CDN, Bootstrap, or
  custom inline CSS)
- A nav with the primary site name + nav links + secondary links
- A footer with copyright + footer links
- The chromeInjection HTML, inserted at the location it specifies
- The literal string "{BODY}" exactly once, where page content goes`

const userPrompt = (theme, chromeInjection) => `Generate a chrome template (header + footer) for this site:

THEME:
${JSON.stringify(theme, null, 2)}

CHROME INJECTION (must be included at the specified location):
${JSON.stringify(chromeInjection, null, 2)}

Requirements:
- Tailwind via CDN if cssApproach is "tailwind-modern" or "tailwind-dated"
- Custom inline <style> block if cssApproach is "custom-css"
- Minimal inline styling if cssApproach is "minimal-utility"
- Bootstrap 5 via CDN if cssApproach is "bootstrap-classic"
- Match the vibe ("${theme.vibe}") — modern apps are clean; dated/legacy apps
  use older styling conventions
- Use ${theme.primaryColor} as the dominant brand color
- Load the "${theme.font}" font from Google Fonts (CSS2 API); fallback to ${theme.fontFallback}
- Header must contain site name "${theme.siteName}" and all navLinks/secondaryLinks
- Footer must contain copyright + all footerLinks
- INSERT the chromeInjection.html at the chromeInjection.location:
  * "header-search" → into the top header bar (a search bar location)
  * "header-end" → at the end of the header nav
  * "footer" → into the footer (above or below the existing footer content)
  * "nav-extra" → as an additional nav link in the main nav
- The HTML must contain exactly one "{BODY}" placeholder — this is where page
  bodies will be inserted
- Output a single complete HTML document starting with <!doctype html>

Return ONLY the HTML. No markdown fences. No commentary.`

export async function generateChrome(theme, chromeInjection) {
  return callLLM({
    system: SYSTEM,
    user: userPrompt(theme, chromeInjection),
    expectJson: false,
    maxTokens: 4096,
  })
}
