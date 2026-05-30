// Adds Karpathy's "2025 LLM Year in Review" post as reference [8] and
// links it into the Jaggedness section to give the framing intellectual
// lineage in practitioner discourse.

import fs from 'node:fs/promises'
import path from 'node:path'

const PLAN_PATH = path.join(process.cwd(), 'plan.html')
let plan = await fs.readFile(PLAN_PATH, 'utf-8')
let applied = 0, skipped = 0, missing = 0

function apply(label, from, to) {
  if (plan.includes(to)) { console.log(`  · ${label}  (already applied)`); skipped++; return }
  if (!plan.includes(from)) { console.log(`  ! ${label}  (anchor not found)`); missing++; return }
  plan = plan.replace(from, to)
  console.log(`  + ${label}`)
  applied++
}

console.log('Karpathy [8] + Jaggedness footnote link')
console.log('━'.repeat(72))

// 1. Add a footnote-style acknowledgment in the Jaggedness section
apply(
  'Jaggedness: Karpathy attribution',
  'Capability that has been jaggedly trained toward bench-shaped patterns is exactly the capability that fails to transfer under defence.',
  'The jagged-capability framing has been popularised in practitioner discourse by Karpathy [8], who describes the dynamic as labs *"constructing environments adjacent to little pockets of the embedding space occupied by benchmarks and growing jaggies to cover them"* — *"training on the test set is a new art form."* This paper formalises the same observation as a structural property of contemporary frontier evaluation, and proposes a methodology that surfaces it as measurement. Capability that has been jaggedly trained toward bench-shaped patterns is exactly the capability that fails to transfer under defence.',
)

// 2. Add reference [8] to the References section
const refAnchor = '**[5] Anthropic** (2026). *Claude Mythos Preview System Card.*'

const newRef8 = `**[8] Karpathy, A.** (2025, December). *2025 LLM Year in Review.* X (Twitter). <https://x.com/karpathy/status/2002118205729562949>

> Section 2 ("Ghosts vs. Animals / Jagged Intelligence") characterises modern frontier-LLM capability as structurally jagged: *"they are at the same time a genius polymath and a confused and cognitively challenged grade schooler."* The post is the most-cited popular articulation of the *benchmaxxing* failure mode: *"benchmarks are almost by construction verifiable environments and are therefore immediately susceptible to RLVR and weaker forms of it via synthetic data generation. In the typical benchmaxxing process, teams in LLM labs inevitably construct environments adjacent to little pockets of the embedding space occupied by benchmarks and grow jaggies to cover them. Training on the test set is a new art form."* PolyRange's randomisation-and-defence methodology is designed to surface the jagged trough that this dynamic obscures.

`

// Insert [8] BEFORE [5] anchor (since references are ordered, but we'll just append for now —
// the convention in the existing References block lists [1] through [5], so we'll insert [8]
// after [5] to keep the numerical order even if it appears physically after.)
// Actually: keep the numbered order 1,2,3,4,5,8 — we're skipping 6 and 7 because those refs
// haven't been verified yet. Add [8] at the END of References, just before the closing marker.

const refEndMarker = '<!-- POLYRANGE_REFERENCES_END -->'

if (plan.includes(newRef8.trim())) {
  console.log('  · References: Karpathy [8]  (already applied)')
  skipped++
} else if (plan.includes(refEndMarker)) {
  plan = plan.replace(refEndMarker, newRef8 + '---\n' + refEndMarker)
  console.log('  + References: Karpathy [8] appended')
  applied++
} else {
  console.log('  ! References: closing marker not found')
  missing++
}

await fs.writeFile(PLAN_PATH, plan)

console.log('━'.repeat(72))
console.log(`  ${applied} applied · ${skipped} already in place · ${missing} anchors missing`)
console.log()
if (missing === 0) console.log('  open plan.html')
