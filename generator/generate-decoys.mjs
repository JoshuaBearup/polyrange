// Generate decoy page bodies for all nav and footer links in the theme.
// Each decoy is visually realistic but not functionally interactive.

import { callLLM } from './call-llm.mjs'

const SYSTEM = `You generate decoy page bodies for synthetic web applications.

Each decoy page is the inner content (no html/head/body tags) for a specific
URL path in a site. Decoys must look like real pages on the site, but
do NOT need to be functionally interactive — forms can render but don't need
to actually submit anywhere meaningful, links to deep pages can exist but
don't need to resolve.

NEVER produce:
- Lorem ipsum or obvious placeholder text
- "polyrange", "benchmark", "test", "demo" anywhere
- Pages that contain user-input reflection points (do not introduce additional
  attack surface — keep all dynamic-feeling content as STATIC HTML)
- Form actions that would be exploitable (use plausible-looking action URLs but
  do not echo any user input)

ALWAYS produce:
- A coherent page body matching the site's industry and vibe
- Realistic-feeling content (real-sounding product names, real-sounding copy,
  realistic prices, realistic UI patterns)
- Same Tailwind/CSS classes as the chrome would use
- 30-80 lines of HTML for category/listing pages
- 15-40 lines for forms or simple status pages
- 30-60 lines for policy pages`

const userPrompt = (theme, link, pageRole) => `Generate the inner page body for "${link.path}" on this site:

${JSON.stringify(theme, null, 2)}

The page is a: ${pageRole}
The page should match the site's "${theme.vibe}" vibe.

Return ONLY the HTML body (no html/head/body wrappers, no markdown fences, no commentary).
Start with a <main> or <div> tag.`

const ROLES = {
  // Common e-commerce / retail patterns
  '/shop': 'product listing grid with filter sidebar',
  '/cart': 'cart page (showing empty cart state)',
  '/account': 'sign-in form (email + password + remember me + forgot link)',
  '/login': 'sign-in form (email + password + remember me + forgot link)',
  '/signin': 'sign-in form',
  '/register': 'sign-up form',
  '/sale': 'sale items grid with discount badges',
  '/wholesale': 'wholesale information page with contact CTA',
  '/about': 'About Us page with company story',
  '/contact': 'contact page with form and contact details',
  '/privacy': 'privacy policy with multiple sections',
  '/terms': 'terms of service with multiple sections',
  '/shipping': 'shipping and returns policy page',
  '/subscriptions': 'subscription tier selection page',
  '/pricing': 'pricing tier selection page',
  '/guides': 'list of articles or guides',
  '/blog': 'blog post listing',
  '/news': 'recent news listing',
  '/roastery': 'about-the-business detail page',
  '/categories': 'category overview',
  '/products': 'product listing',
  '/features': 'feature list with icons',
  '/docs': 'documentation home page',
  '/faq': 'frequently asked questions',
  '/careers': 'careers page with open positions',
}

function inferRole(link) {
  // Try exact path match first
  if (ROLES[link.path]) return ROLES[link.path]
  // Try prefix match
  for (const [pathPrefix, role] of Object.entries(ROLES)) {
    if (link.path.startsWith(pathPrefix)) return role
  }
  // Fall back on label semantics
  const label = link.label.toLowerCase()
  if (label.includes('cart') || label.includes('basket')) return 'shopping cart page'
  if (label.includes('sign') || label.includes('login')) return 'sign-in form'
  if (label.includes('account') || label.includes('profile')) return 'account dashboard or sign-in page'
  if (label.includes('contact')) return 'contact page'
  if (label.includes('about')) return 'about-the-company page'
  if (label.includes('privacy')) return 'privacy policy'
  if (label.includes('terms')) return 'terms of service'
  if (label.includes('pricing') || label.includes('plans')) return 'pricing tiers'
  if (label.includes('blog') || label.includes('news') || label.includes('article')) return 'article listing'
  if (label.includes('product') || label.includes('shop')) return 'product listing grid'
  if (label.includes('category') || label.includes('categories')) return 'category overview'
  // Generic fallback
  return `landing page for "${link.label}" relevant to this site's industry`
}

export async function generateDecoyPage(theme, link) {
  const role = inferRole(link)
  const body = await callLLM({
    system: SYSTEM,
    user: userPrompt(theme, link, role),
    expectJson: false,
    maxTokens: 3000,
  })
  // Strip optional markdown fence if model added one despite instructions
  const cleaned = body.replace(/^```(?:html)?\s*/m, '').replace(/\s*```\s*$/m, '').trim()
  return { title: link.label, body: cleaned }
}

// Also generate a homepage decoy at "/"
export async function generateHomepage(theme) {
  const body = await callLLM({
    system: SYSTEM,
    user: `Generate the homepage body for this site:

${JSON.stringify(theme, null, 2)}

The homepage should include:
- A hero section with the tagline "${theme.tagline}" and the blurb "${theme.homepageHeroBlurb}"
- The main content described as: "${theme.homepageDescription}"
- Should feel like a real homepage for the site's industry

Return ONLY the HTML body. No html/head/body wrappers. No markdown fences. No commentary.`,
    maxTokens: 3500,
  })
  const cleaned = body.replace(/^```(?:html)?\s*/m, '').replace(/\s*```\s*$/m, '').trim()
  return { title: 'Home', body: cleaned }
}
