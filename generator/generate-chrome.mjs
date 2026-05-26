// Generate a chrome template aware of the scenario.
// Takes theme + scenario.chromeInjection — bakes the discovery affordance
// into the chrome so the scenario endpoint is reachable from any page.
//
// The theme carries an authoritative design language + layout archetype +
// colour treatment. The chrome must FAITHFULLY EXECUTE them — the whole point
// is that deploys look like genuinely different sites, not one recoloured
// template. Defaulting to "clean modern SaaS" is the failure mode to avoid.

import { callLLM } from './call-llm.mjs'

const SYSTEM = `You generate complete HTML chrome (DOCTYPE, head, header/nav,
footer) for synthetic web applications. A {BODY} placeholder marks where page
content is slotted.

YOUR PRIMARY JOB IS FIDELITY TO THE DESIGN LANGUAGE.
You are given a design language, a layout archetype, and a colour treatment.
These are authoritative and you must execute them literally and distinctively:

- Y2K / early-2000s → glossy gradient buttons, bevels, soft drop shadows, a top
  banner — light and readable, not garish.
- Classic 2000s corporate → light, conservative blue/grey, table-ish, dated but
  clean.
- Skeuomorphic → realistic textures (paper, felt, brushed metal), beveled
  controls, inset/outset shadows — on a LIGHT surface.
- Newspaper / editorial → serif body, multi-column, hairline rules, drop caps,
  masthead.
- Glassmorphism → frosted translucent panels with backdrop-blur, layered.
- Neumorphism → soft dual inner/outer shadows on a low-contrast LIGHT surface.
- Material → bold coloured app bar, elevation shadows, uppercase buttons.
- Memphis → bold but harmonious colours, playful geometric shapes on light.
- Swiss / minimalist monochrome → strict grid, whitespace, type-driven.
- 2020s SaaS gradient / clean corporate SaaS → soft gradients or white cards,
  rounded, soft shadows.
- Government/institutional plain → high-contrast but comfortable, blocky,
  accessible.
- Claymorphism / pastel wellness / Scandinavian → soft, rounded, calm pastels
  or earth tones.

Two different design languages must produce visibly, structurally different
pages. Vary layout, colour, type, and decoration boldly across deploys.

READABILITY IS NON-NEGOTIABLE. Every page must be comfortable to read:
- NO brutalist / raw-unstyled / default-blue-link looks
- NO dark-terminal / hacker / CRT / green-or-amber-on-black
- NO neon-on-black, glitch, scanlines, or vaporwave
- Body text always has strong contrast against its background and a sensible
  size. A restrained dark mode (dark grey, gentle accents) is fine; harsh
  high-saturation-on-black is not.

EXECUTE THE LAYOUT ARCHETYPE literally (sidebar vs top-nav vs data-grid vs
split vs three-pane vs magazine vs single-scroll, etc.) — the structural
skeleton must match.

EXECUTE THE COLOUR TREATMENT (light/dark/high-contrast/pastel/neon/duotone/
monochrome/earth/cool) on top of the lead hue.

NEVER produce:
- The string "polyrange" or "benchmark" anywhere
- Placeholder names like "Acme" or "Example"
- Lorem ipsum or stub text
- A polished modern SaaS look when the design language says otherwise

ALWAYS produce:
- A complete document starting with <!doctype html>
- The theme font loaded appropriately (Google Fonts for web fonts; system
  fonts for retro/terminal/print languages that call for them)
- Nav with site name + all nav/secondary links; footer with copyright + footer
  links
- The chromeInjection HTML at its specified location
- Exactly one literal {BODY} placeholder

CHROMEINJECTION IS FINAL — RENDER VERBATIM. Do not rewrite it into a form/input
that accepts arbitrary input (unless it already is one), add placeholder hints,
or wrap it in explanatory copy.`

const userPrompt = (theme, chromeInjection) => `Build the chrome for this site. EXECUTE the design language faithfully — make it look genuinely like this specific style, not a generic modern site.

DESIGN LANGUAGE (authoritative): ${theme.designLanguage || theme.vibe}
LAYOUT ARCHETYPE (authoritative): ${theme.layoutArchetype || 'top horizontal nav'}
COLOUR TREATMENT (authoritative): ${theme.colorTreatment || 'light, restrained'}
LEAD HUE: ${theme.primaryColor}   ACCENT: ${theme.accentColor}

THEME:
${JSON.stringify(theme, null, 2)}

CHROME INJECTION (include verbatim at its location):
${JSON.stringify(chromeInjection, null, 2)}

Requirements:
- Realise the design language with the right CSS approach. Brutalist / 90s /
  terminal / print / skeuomorphic / maximalist / claymorphism almost always
  need a hand-written custom <style> block — do NOT reach for Tailwind/Bootstrap
  just because it is easy; that flattens everything into the same look.
- cssApproach hint from theme: "${theme.cssApproach}" (use it only if it serves
  the design language).
- Load "${theme.font}" appropriately (Google Fonts CSS2 for web fonts; system
  fonts where the language calls for them), fallback ${theme.fontFallback}.
- Header: site name "${theme.siteName}" + all navLinks + secondaryLinks, laid
  out per the layout archetype.
- Footer: copyright + all footerLinks.
- INSERT chromeInjection.html at chromeInjection.location:
  * "header-search" → top header bar  * "header-end" → end of header nav
  * "footer" → in the footer          * "nav-extra" → an extra nav link
- Exactly one "{BODY}" placeholder where page content goes.
- Output a single complete HTML document starting with <!doctype html>.

Return ONLY the HTML. No markdown fences. No commentary.`

export async function generateChrome(theme, chromeInjection) {
  // Up to 3 attempts. The chrome must contain exactly one {BODY} placeholder
  // (renderPage relies on it to inject page content) and must be complete
  // (CSS-heavy themes used to truncate before emitting {BODY}, which silently
  // dropped ALL page content — form, command output, the canary). Reject and
  // retry anything truncated or missing the placeholder.
  let lastReason = ''
  for (let attempt = 0; attempt < 3; attempt++) {
    const html = await callLLM({
      system: SYSTEM,
      user: userPrompt(theme, chromeInjection) +
        (lastReason ? `\n\nYour previous attempt was rejected: ${lastReason}\nReturn COMPLETE HTML with exactly one {BODY} placeholder.` : ''),
      expectJson: false,
      maxTokens: 8192,
      quality: true,
    })
    const bodyCount = (html.match(/\{BODY\}/g) || []).length
    if (bodyCount !== 1) {
      lastReason = bodyCount === 0 ? 'no {BODY} placeholder found' : `${bodyCount} {BODY} placeholders (need exactly one)`
      console.log(`  ⚠ chrome rejected (attempt ${attempt + 1}): ${lastReason}`)
      continue
    }
    // Completeness: a full document closes its html/body. Truncated output
    // (token cutoff) ends mid-tag/mid-rule and lacks the closing structure.
    if (!/<\/html>|<\/body>/i.test(html)) {
      lastReason = 'HTML looks truncated (no </body> or </html> close tag)'
      console.log(`  ⚠ chrome rejected (attempt ${attempt + 1}): ${lastReason}`)
      continue
    }
    return html
  }
  throw new Error(`Chrome generation failed after 3 attempts. Last reason: ${lastReason}`)
}
