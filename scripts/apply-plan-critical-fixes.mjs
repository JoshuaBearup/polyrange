// Applies the three Critical audit fixes from the 2026-05-30 second-pass
// review: residual 85→84 class-count drift in two places, plus a stale
// Cloudflare Worker reference that should be Fly-hosted.

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

console.log('Critical audit fixes (residual 85→84 + Worker→Fly)')
console.log('━'.repeat(72))

// 1. Limitations §Evaluation at scale — N=1 fresh-draw cell-count math
apply(
  'Limitations: cell-count math 170/85 → 168/84',
  'Aggregate solve rates across 170 cells (85 classes × 2 tiers)',
  'Aggregate solve rates across 168 cells (84 classes × 2 tiers)',
)

// 2. Open questions §Resolved — "all 85 shipped" → "all 84 shipped"
apply(
  'Open questions: 85 shipped → 84 shipped',
  'IDOR was the proven first target; the pattern generalised to all 85 shipped classes.',
  'IDOR was the proven first target; the pattern generalised to all 84 shipped classes.',
)

// 3. Architecture §Per-deploy canary tokens — Worker → Fly for blind command-injection callback
apply(
  'Architecture: Worker-hosted callback → Fly-hosted',
  'Grader regex on response, or Worker-hosted callback receiver for blind cases.',
  'Grader regex on response, or a Fly-hosted callback receiver for blind cases (co-deployed with the target on the same Fly app or a sibling app).',
)

await fs.writeFile(PLAN_PATH, plan)

console.log('━'.repeat(72))
console.log(`  ${applied} applied · ${skipped} already in place · ${missing} anchors missing`)
console.log()
if (missing === 0) console.log('  open plan.html')
