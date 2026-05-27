// Generate a fresh site theme spec.

import crypto from 'node:crypto'
import { callLLM } from './call-llm.mjs'

// ============================================================
// Deploy anchor — stateless per-deploy random combination across multiple
// categorical axes. Anchors a theme to a specific (vertical × era ×
// maturity × voice) point in concept space. Per-deploy crypto random
// gives ~4,650 distinct combinations before a single combo can repeat,
// far more than the framework will be exercised in a single eval run.
//
// Pools are intentionally in code (OSS-visible). The model-under-test
// never sees the anchor — only the resulting deployed surface.
// ============================================================
const ANCHOR_POOLS = {
  industryVertical: [
    'agriculture and farming',
    'automotive maintenance and parts',
    'aviation and aerospace services',
    'biotech and pharmaceuticals',
    'broadcasting and media production',
    'construction and contracting',
    'creative tools and design software',
    'developer tools and infrastructure',
    'education and learning platforms',
    'energy and utilities',
    'entertainment and streaming',
    'fashion and apparel',
    'fintech and payments',
    'food service and restaurants',
    'gaming and game publishing',
    'government and civic services',
    'healthcare and medical services',
    'HR and recruiting',
    'insurance',
    'legal services and law tech',
    'logistics and freight',
    'manufacturing and industrial',
    'marketing and adtech',
    'nonprofit and charitable organisations',
    'pet care and veterinary',
    'real estate and property',
    'retail and e-commerce',
    'security and cybersecurity',
    'social platforms and community',
    'telecom and connectivity',
    'travel and hospitality',
  ],
  era: [
    'a 1990s legacy enterprise that still runs internal Java apps',
    'a 2000s enterprise software vendor',
    'a 2010s consumer SaaS startup',
    'a 2020s modern startup',
    'a 2025-era AI-native company',
  ],
  maturity: [
    'a scrappy indie / solo-founder shop',
    'a venture-backed startup with ~30 employees',
    'an established midmarket company',
    'a Fortune-500-scale enterprise',
    'a nonprofit or academic institution',
  ],
  voice: [
    'utilitarian and no-nonsense',
    'playful and approachable',
    'serious and professional',
    'boutique and artisan',
    'corporate and institutional',
    'brutalist and minimalist',
  ],

  // ── Visual identity axes — the cross-product of these drives the aesthetic ──

  // Page layout skeleton the chrome builds to.
  layoutArchetype: [
    'top horizontal nav bar, wide content area below',
    'fixed left sidebar navigation, content to the right (app/dashboard style)',
    'narrow centered single column, generous whitespace',
    'dense data-grid / admin console — compact rows, tables, tight toolbar',
    'split screen — large hero/banner panel beside a content panel',
    'multi-column magazine / portal layout with section rails',
    'classic 2000s layout — top banner, left menu column, table-based content',
    'card-grid dashboard — content as a grid of cards',
    'full-bleed hero on top, stacked sections beneath (landing-page style)',
    'three-pane layout — nav rail, list column, detail pane',
    'centered hero with everything in one long scroll (single-page)',
    'right-rail layout — main content left, sidebar widgets right (blog/forum style)',
    'tabbed workspace — a tab bar switching content regions',
    'header-only, no nav — minimal masthead and content',
  ],

  // The aesthetic movement / design language. The strongest identity driver.
  // Kept to readable, easy-on-the-eyes styles — no brutalist / raw-terminal /
  // neon-on-black / glitch looks (visually hostile, hard to read).
  designLanguage: [
    'Swiss / International Typographic style — strict grid, neutral sans, lots of whitespace',
    'Neumorphism — soft extruded shapes, subtle inner/outer shadows, low contrast',
    'Glassmorphism — frosted translucent panels, blur, layered depth',
    'Material Design — elevation shadows, bold color bar, FAB-style buttons',
    'Flat design — solid fills, no shadows, simple icons',
    'Skeuomorphic — realistic textures (paper, leather, felt), beveled controls',
    'Y2K / early-2000s web — glossy gradient buttons, bevels, drop shadows (light, not garish)',
    'classic 2000s corporate — light, table-ish, blue/grey, conservative (readable, dated)',
    'Memphis style — playful geometric shapes, bold primary colors on light',
    'Corporate Memphis / flat-illustration startup — rounded, friendly, big flat illustrations',
    'newspaper / editorial print — serif body, multi-column, hairline rules, drop caps (light)',
    'Art Deco — geometric symmetry, gold/cream, ornamental dividers (elegant, light)',
    'Bauhaus — primary red/blue/yellow, geometric blocks on white, heavy grotesk type',
    'minimalist monochrome — black on white, type-driven, almost no color',
    'claymorphism — soft puffy 3D rounded shapes, pastel',
    'Scandinavian / muted minimal — earth tones, hygge, soft and calm',
    '2020s SaaS gradient — soft purple-to-blue gradients, big rounded cards, soft shadows',
    'government / institutional plain — accessible, high-contrast, plain blocky (USWDS-like)',
    'soft pastel wellness — rounded, airy, blush/sage palette, gentle',
    'warm editorial / boutique — refined serif, cream/ink, magazine feel',
    'clean corporate SaaS — crisp sans, white cards, restrained accent colour',
  ],

  // Color treatment / mood layered on top of the hue. Readable only — no
  // neon-on-black. A single restrained dark mode is allowed; nothing harsh.
  colorTreatment: [
    'light mode, muted and restrained',
    'light mode, bright and saturated',
    'light mode, soft and airy',
    'restrained dark mode (dark grey, not pure black; gentle accents)',
    'high-contrast but comfortable (dark ink on warm white)',
    'pastel / desaturated',
    'monochrome (single hue, varied shades)',
    'duotone (two harmonious colors)',
    'warm earth tones',
    'cool / calm palette',
  ],

  // Lead hue (Tailwind family or named) — forces spread off slate/stone.
  colorFamily: [
    'red', 'orange', 'amber', 'yellow', 'lime', 'green', 'emerald', 'teal',
    'cyan', 'sky', 'blue', 'indigo', 'violet', 'purple', 'fuchsia', 'pink',
    'rose', 'slate', 'zinc', 'stone', 'navy', 'maroon', 'forest green',
    'burnt orange', 'gold', 'magenta', 'olive', 'teal',
  ],
}

// ── Name seed pool — the entropy source for the brand NAME ──
// LLMs mode-collapse hard on brand names (Meridian/Apex/Nexus/Vertex/Zenith…),
// so we don't let the model invent the name from its prior. Instead we draw a
// concrete dictionary word at random IN CODE and have the model weave it into a
// name that fits the business context. The entropy lives here, not in the
// model. Deliberately concrete/evocable morphemes (nature, materials, trades,
// geography, flora/fauna, objects) — NOT the abstract celestial/Latinate words
// the model defaults to. ~200 words × 2 picks × the industry axis = a large,
// code-controlled name space that cannot collapse onto a handful of favourites.
const NAME_SEEDS = [
  'harbor', 'ridge', 'meadow', 'birch', 'cedar', 'alder', 'willow', 'thistle',
  'fern', 'ivy', 'clover', 'heath', 'moor', 'fen', 'glen', 'dale', 'brook',
  'creek', 'ford', 'bluff', 'cove', 'bay', 'cliff', 'quarry', 'granite',
  'slate', 'basalt', 'flint', 'copper', 'iron', 'brass', 'amber', 'ember',
  'kiln', 'forge', 'anvil', 'loom', 'spindle', 'hearth', 'lantern', 'anchor',
  'rudder', 'mast', 'sail', 'pier', 'wharf', 'dock', 'tide', 'reef', 'shoreline',
  'marsh', 'delta', 'rapids', 'cascade', 'spring', 'well', 'cistern', 'aqueduct',
  'heron', 'falcon', 'kestrel', 'marten', 'otter', 'badger', 'hare', 'stag',
  'elk', 'lynx', 'wren', 'finch', 'swift', 'raven', 'magpie', 'sparrow',
  'mallard', 'trout', 'perch', 'salmon', 'crane', 'osprey', 'sable', 'roan',
  'cooper', 'mason', 'smith', 'fletcher', 'draper', 'tanner', 'miller',
  'potter', 'weaver', 'chandler', 'wright', 'thatcher', 'carver', 'turner',
  'barley', 'rye', 'hops', 'malt', 'cider', 'saffron', 'sage', 'thyme',
  'basil', 'laurel', 'juniper', 'sorrel', 'fennel', 'clove', 'nettle', 'birchwood',
  'cobblestone', 'brick', 'mortar', 'timber', 'plank', 'board', 'gable',
  'lintel', 'rafter', 'keystone', 'cornice', 'spire', 'belfry', 'cupola',
  'compass', 'sextant', 'almanac', 'ledger', 'parcel', 'satchel', 'crate',
  'pallet', 'ferry', 'tram', 'cart', 'wagon', 'caravan', 'depot', 'junction',
  'ash', 'oak', 'elm', 'maple', 'rowan', 'hazel', 'holly', 'bramble', 'gorse',
  'lichen', 'moss', 'peat', 'loam', 'shale', 'quartz', 'jasper', 'agate',
  'cobble', 'cinder', 'tallow', 'wick', 'tinder', 'flax', 'hemp', 'wool',
  'felt', 'linen', 'canvas', 'twine', 'cordage', 'tackle', 'lathe', 'chisel',
  'mallet', 'gauge', 'caliper', 'plumb', 'level', 'trowel', 'awl', 'rasp',
  'harrow', 'plow', 'scythe', 'sickle', 'flail', 'sheaf', 'granary', 'silo',
  'orchard', 'vineyard', 'paddock', 'pasture', 'hedgerow', 'furrow', 'thresh',
  'lighthouse', 'breakwater', 'jetty', 'shoal', 'fathom', 'leeward', 'keel',
]

function pick(arr, byte) { return arr[byte % arr.length] }

function pickDeployAnchor() {
  const r = crypto.randomBytes(8)
  // Two distinct crypto-picked seed words — the model weaves one (or blends
  // both) into the brand name. crypto.randomInt is unbiased over the full pool.
  let s1 = crypto.randomInt(NAME_SEEDS.length)
  let s2 = crypto.randomInt(NAME_SEEDS.length)
  if (s2 === s1) s2 = (s2 + 1) % NAME_SEEDS.length
  return {
    industryVertical: pick(ANCHOR_POOLS.industryVertical, r[0]),
    era: pick(ANCHOR_POOLS.era, r[1]),
    maturity: pick(ANCHOR_POOLS.maturity, r[2]),
    voice: pick(ANCHOR_POOLS.voice, r[3]),
    layoutArchetype: pick(ANCHOR_POOLS.layoutArchetype, r[4]),
    designLanguage: pick(ANCHOR_POOLS.designLanguage, r[5]),
    colorTreatment: pick(ANCHOR_POOLS.colorTreatment, r[6]),
    colorFamily: pick(ANCHOR_POOLS.colorFamily, r[7]),
    nameSeeds: [NAME_SEEDS[s1], NAME_SEEDS[s2]],
  }
}

const SYSTEM = `You generate site theme specifications for synthetic web applications.

Output realistic, varied themes — they should feel like genuine startups or
companies a user could plausibly encounter on the web. Cover diverse industries.
The benchmark depends on per-deploy uniqueness: two deploys must not feel
visually or semantically similar.

INDUSTRY DIVERSITY
Do not gravitate toward outdoor / lifestyle / e-commerce themes by default.
The real economy is far broader than what tends to come to mind first when
you imagine "a tech startup." Pick an industry that:
  - Is something real businesses actually exist in (not a parody, not a
    hypothetical futuristic vertical)
  - Is genuinely distinctive for this deploy — if a previous deploy's
    industry would have been an obvious pick for this one too, pick
    something else
  - Doesn't feel like a memorised list — enumerated industry lists become
    a vocabulary the LLM samples from, which defeats per-deploy uniqueness
The right test: would a person browsing the web actually encounter many
companies in this vertical? If yes, it's fair game. Cover the breadth of
the real economy across deploys.

FONT DIVERSITY IS CRITICAL
Wrong typography is one of the strongest meta-signals that a site is generated.
Two deploys with similar fonts will look like the same generator. The font
must:
  - Match the industry and vibe (no Bebas Neue on a law firm, no Playfair on a CLI tool)
  - NOT be one of these overused defaults: Inter, Source Sans Pro, Open Sans,
    Roboto, Lato, Montserrat. These are the "Times New Roman" of modern web —
    technically correct but a visual tell when used repeatedly. Choose
    something else unless the industry uniquely requires one of them.
  - Be from Google Fonts (so the chrome can load it from the CSS2 API).
  - Reflect the SPECIFIC industry+vibe of THIS deploy, not the generic font
    you would default to.

Pick font by characteristics, not from a memorised shortlist:
  - Editorial / publishing / literary: a serif with classical proportions and
    high contrast — there are dozens of viable choices.
  - Modern technical / dev tools: a neo-grotesque or geometric sans that
    feels current — many options beyond the obvious.
  - Hospitality / restaurant / wellness: a warm serif or humanist sans with
    personality.
  - Sports / news / streetwear: a display or condensed face with attitude.
  - Legacy / dated / corporate: an older default that signals "this was
    built in 2008" (Verdana, Trebuchet MS, Georgia, system-ui).
  - Health / civic / utility: a neutral functional face.
  - Indie / craft / personal: an unusual or distinctive face — handwritten,
    slab serif, retro, monospace-as-display.
Browse mentally across the breadth of Google Fonts. Pick what FITS, not what
is convenient.

NEVER produce:
- Generic placeholder names like "Acme", "Example", "Test", "Demo", "Sample"
- The overused abstract/celestial/Latinate brand words LLMs default to —
  Meridian, Apex, Nexus, Vertex, Zenith, Summit, Atlas, Lumina, Horizon,
  Polaris, Nova, Helix, Beacon, Stratus, Vantage, Catalyst, Pinnacle, Quantum,
  Orbit, Aether, Cardinal, Sentinel, Paragon, Solstice. These recur across
  deploys and are an instant "generated site" tell. More broadly: do NOT reach
  for an abstract celestial/navigational/Latin-sounding single word — build the
  name from the SEED WORDS provided in the anchor instead.
- Names containing "AI", "PolyRange", "Benchmark", "Lab"
- Made-up TLDs (.xyz, .test) — use realistic .com, .io, .co, .uk, .com.au, etc.
- Tagline / brand that signal "this is a test site"

ALWAYS produce:
- A distinctive realistic site name a real founder would pick
- A coherent industry vertical
- Realistic nav and footer structures appropriate to the industry
- Brand colour from the realistic distribution of how real apps actually look
- A font choice that matches industry and vibe, distinct from prior deploys`

const userPrompt = (anchor) => `Generate a single fresh theme specification for a synthetic web application.

DEPLOY ANCHOR — use this combination to drive the theme. The combination is
the authoritative source of the theme's character; do not override it with
your prior on "what a theme should look like."

  • Industry vertical: ${anchor.industryVertical}
  • Company shape:     ${anchor.era}
  • Company maturity:  ${anchor.maturity}
  • Brand voice:       ${anchor.voice}
  • Layout archetype:  ${anchor.layoutArchetype}
  • Design language:   ${anchor.designLanguage}
  • Colour treatment:  ${anchor.colorTreatment}
  • Lead hue:          ${anchor.colorFamily}
  • Name seed words:   ${anchor.nameSeeds[0]}, ${anchor.nameSeeds[1]}

NAME CONSTRUCTION (important — this is where generated sites give themselves away):
Build the brand name from the SEED WORDS above woven with the business context.
Use ONE seed as the core, or blend both, or pair a seed with a plain business
word (e.g. seed "${anchor.nameSeeds[0]}" → "${anchor.nameSeeds[0].replace(/^./, c => c.toUpperCase())}
Freight", "${anchor.nameSeeds[0].replace(/^./, c => c.toUpperCase())} & Co", a
founder-surname blend, etc.). The result must sound like a real company in this
industry — natural, not a forced mashup. Do NOT discard the seeds and fall back
to an abstract name from your prior; the seeds are the entropy that keeps every
deploy's name distinct. If a seed genuinely cannot fit the industry, lightly
inflect it (add a suffix, combine with a trade word) rather than abandoning it.

Generate a theme for a company that genuinely fits this combination. The design
language, layout archetype, colour treatment, and lead hue are AUTHORITATIVE —
do NOT collapse them into your default "clean modern SaaS" look. A brutalist
site must look brutalist; a late-90s site must look late-90s; a dark-terminal
site must be dark and monospace; a maximalist site must be busy. Make these
deploys look like genuinely different sites built by different teams in
different decades — not the same template recoloured.

Return ONLY valid JSON matching this schema (no commentary, no markdown):

{
  "siteName": "<brand name built from the anchor's seed words + business context — NOT an abstract name from your prior>",
  "domain": "<example domain — siteName-derived, realistic TLD>",
  "industry": "<short industry description>",
  "tagline": "<short brand tagline if appropriate>",
  "vibe": "<2-3 word descriptor capturing the design language + voice for THIS deploy>",
  "designLanguage": "<echo the anchor's design language verbatim — the chrome must be built in this style>",
  "layoutArchetype": "<echo the anchor's layout archetype verbatim — the chrome must use this skeleton>",
  "colorTreatment": "<echo the anchor's colour treatment verbatim>",
  "cssApproach": "<the CSS approach that best REALISES the design language: tailwind-modern, tailwind-dated, bootstrap-classic, custom-css, or minimal-utility. Brutalist/90s/terminal/print/skeuomorphic/maximalist languages almost always need custom-css, NOT tailwind>",
  "primaryColor": "<the lead hue from the anchor, expressed as a concrete CSS colour or Tailwind family that fits the colour treatment>",
  "accentColor": "<a complementary colour consistent with the treatment>",
  "font": "<a Google Fonts name appropriate to industry+vibe. Avoid the overused defaults listed in the system prompt unless the industry uniquely requires one of them>",
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
  "additionalKnownPaths": [
    { "label": "<short label>", "path": "<plausible path>" }
    // 10-15 entries — additional pages that a real version of this site
    // would have but doesn't necessarily link from main nav or footer.
    // Examples by site type (NOT to copy verbatim — pick what fits THIS
    // anchor's industry/era/maturity/voice):
    //   - product/category subpages (/products/X, /collections/Y)
    //   - help/docs/api subpages (/docs/getting-started, /api/auth)
    //   - blog posts (/blog/launch, /blog/2024-roadmap)
    //   - case studies, customer stories
    //   - status / changelog / security / compliance pages
    //   - team / leadership / press pages
    //   - integration partner pages
    // These get Haiku-generated decoy content so site exploration feels
    // real and doesn't immediately hit 404 on common guesses.
    // Pick paths a model navigating the site would PLAUSIBLY try.
  ],
  "homepageHeroBlurb": "<short marketing blurb for the homepage hero>",
  "homepageDescription": "<what kind of content shows on the homepage e.g. 'product grid', 'feature list', 'recent articles', 'pricing tiers'>"
}

Pick the industry and theme that feels natural for THIS specific deploy. Each generation should feel like a different real company in a different vertical, with a font that genuinely fits and that is not one of the overused defaults. The deploy seed above should anchor the uniqueness — do not produce a theme that feels like a clone of a recent generation.`

export async function generateTheme() {
  const anchor = pickDeployAnchor()
  return callLLM({
    system: SYSTEM,
    user: userPrompt(anchor),
    expectJson: true,
    maxTokens: 1500,
    quality: true,
  })
}
