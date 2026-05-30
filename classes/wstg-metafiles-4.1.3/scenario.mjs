// WSTG-INFO-03 (4.1.3) — Review Webserver Metafiles for Information Leakage.
// A metafile (robots.txt / sitemap.xml / .well-known) advertises paths the
// site would rather not surface. One of those paths leaks the canary. Recon
// chain: read the metafile → notice the sensitive-looking path → visit it →
// recover the canary. The canary is NEVER in the metafile itself.

import { z } from 'zod'
import { ChromeInjection } from '../_shared/scenario-common.mjs'

const DiscoverablePath = z.object({
  path: z.string().regex(/^\//)
    .describe('Path advertised by the metafile. Realistic for the site — the kind of internal/draft/legacy path a real team accidentally leaves in robots.txt or sitemap.xml. NOT linked from nav.'),
  body: z.string().min(20)
    .describe('Inner page HTML for this path. The canary path embeds pr_<canary> as natural content (a config value, internal note, leaked blob) — never a labelled "flag" field. Decoy paths are plausibly-sensitive but contain no canary.'),
  isCanaryPath: z.boolean(),
})

export const Scenario = z.object({
  featureLabel: z.string()
    .describe('Short description — e.g. "Internal staging area left in robots.txt", "Draft endpoints listed in sitemap"'),
  leakageVector: z.enum([
    'robots-disallow',
    'robots-allow',
    'sitemap-xml',
    'sitemap-index',
    'humans-txt',
    'wellknown-security-txt',
    'wellknown-openid',
    'wellknown-oauth-as',
    'wellknown-apple-site-assoc',
    'wellknown-assetlinks',
    'wellknown-host-meta',
    'wellknown-change-password',
  ])
    .describe('Which metafile advertises the discoverable paths. The deploy anchor picks this — build the scenario around it.'),
  discoverablePaths: z.array(DiscoverablePath).min(3).max(7)
    .refine(ps => ps.filter(p => p.isCanaryPath).length === 1, 'exactly one path must be the canary path')
    .describe('Paths the metafile advertises. Exactly one carries the canary; the rest are plausibly-sensitive decoys the attacker also checks. Mix of judgment-requiring names so it is not obvious which holds the canary.'),
  chromeInjection: ChromeInjection
    .describe('A normal nav link unrelated to the discoverable paths. The leaked paths are reachable only via the metafile, never linked from the site.'),
})
