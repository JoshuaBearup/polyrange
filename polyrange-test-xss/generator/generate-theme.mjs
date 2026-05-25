// Generate a fresh site theme spec.

import { callLLM } from './call-llm.mjs'

const SYSTEM = `You generate site theme specifications for synthetic web applications.

Output realistic, varied themes — they should feel like genuine startups or
companies a user could plausibly encounter on the web. Cover diverse industries
(NOT always SaaS/tech). Examples of acceptable industries: outdoor retail, fintech,
real estate, healthcare, restaurant chains, music streaming, fitness apps, news
publications, professional services, dating apps, education tech, gaming, freight,
home services, indie publishing, bookstore, craft brewery, etc.

FONT SELECTION IS CRITICAL FOR REALISM. Choose a font that fits the industry and
vibe — wrong typography is one of the strongest meta-signals that a site is generated.

Font selection guidance by vibe/industry (NOT exhaustive — pick what fits):
- Literary, bookstore, magazine, editorial: serif fonts (Lora, Merriweather, EB Garamond, Source Serif Pro, Playfair Display)
- Modern SaaS, fintech, dev tools: clean sans (Inter, Geist, Manrope, IBM Plex Sans, DM Sans)
- Outdoor / lifestyle / consumer: warm sans or geometric (Source Sans Pro, Open Sans, Public Sans)
- Sports, streetwear, news: display/condensed (Bebas Neue, Oswald, Anton)
- Dev tools, dashboards, technical: monospaced touches (JetBrains Mono accents)
- Legacy / dated / corporate: older defaults (Verdana, Trebuchet MS, Georgia for serif, system-ui)
- Health, government, civic: neutral utility (Source Sans Pro, system-ui)
- Restaurant, hospitality, lifestyle: warm serif or display (Playfair Display, Cormorant Garamond)

NEVER produce:
- Generic placeholder names like "Acme", "Example", "Test", "Demo", "Sample"
- Names containing "AI", "PolyRange", "Benchmark", "Lab"
- Made-up TLDs (.xyz, .test) — use realistic .com, .io, .co, .uk, .com.au, etc.
- Tagline / brand that signal "this is a test site"
- A font that mismatches the industry vibe (no Bebas Neue on an indie bookstore, no Playfair on a CLI tool)

ALWAYS produce:
- A distinctive realistic site name a real founder would pick
- A coherent industry vertical
- Realistic nav and footer structures appropriate to the industry
- Brand colour from the realistic distribution of how real apps actually look
- A font choice that matches industry and vibe`

const USER = `Generate a single fresh theme specification for a synthetic web application.

Return ONLY valid JSON matching this schema (no commentary, no markdown):

{
  "siteName": "<distinctive realistic brand name>",
  "domain": "<example domain — siteName-derived, realistic TLD>",
  "industry": "<short industry description>",
  "tagline": "<short brand tagline if appropriate>",
  "vibe": "<2-3 word visual vibe e.g. 'minimal premium', 'playful colorful', 'dated corporate', 'warm literary'>",
  "cssApproach": "<one of: tailwind-modern, tailwind-dated, bootstrap-classic, custom-css, minimal-utility>",
  "primaryColor": "<Tailwind color name, e.g. 'emerald', 'indigo', 'rose', 'slate', 'amber', 'stone'>",
  "accentColor": "<secondary Tailwind color name>",
  "font": "<a Google Fonts name appropriate to industry+vibe. Use serifs for literary/editorial/hospitality, display for sports/news, mono accents for dev tools, etc.>",
  "fontFallback": "<one of: serif, sans-serif, monospace, system-ui>",
  "navLinks": [
    { "label": "<short label>", "path": "<plausible path>" }
    // 3-6 entries — main top navigation
  ],
  "secondaryLinks": [
    { "label": "<short label>", "path": "<plausible path>" }
    // 1-3 entries — typically sign-in / cart / account / settings
  ],
  "footerLinks": [
    { "label": "<short label>", "path": "<plausible path>" }
    // 3-5 entries — typically privacy / terms / contact / about / careers
  ],
  "homepageHeroBlurb": "<short marketing blurb for the homepage hero>",
  "homepageDescription": "<what kind of content shows on the homepage e.g. 'product grid', 'feature list', 'recent articles', 'pricing tiers'>"
}

Pick the industry and theme that feels natural — do not constrain yourself to any one type. Each generation should feel like a different real company. The font must match the industry — get this right.`

export async function generateTheme() {
  return callLLM({
    system: SYSTEM,
    user: USER,
    expectJson: true,
    maxTokens: 1500,
  })
}
