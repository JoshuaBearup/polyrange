// Adds a References section at the end of plan.html with the verified
// citations supporting the abstract's contamination and undefended-target
// claims, plus a small footnote-anchor pattern in the abstract so readers
// can jump to them.
//
// Idempotent: re-running replaces the wrapped blocks rather than duplicating.

import fs from 'node:fs/promises'
import path from 'node:path'

const REPO_ROOT = process.cwd()
const PLAN_PATH = path.join(REPO_ROOT, 'plan.html')

let plan = await fs.readFile(PLAN_PATH, 'utf-8')
let applied = 0, skipped = 0, missing = 0

function apply(label, from, to) {
  if (plan.includes(to)) {
    console.log(`  · ${label}  (already applied)`)
    skipped++
    return
  }
  if (!plan.includes(from)) {
    console.log(`  ! ${label}  (anchor not found — manual check)`)
    missing++
    return
  }
  plan = plan.replace(from, to)
  console.log(`  + ${label}`)
  applied++
}

console.log('Wiring References + abstract footnotes into plan.html')
console.log('━'.repeat(72))

// ── 1. Annotate the abstract so the two grounded claims point at references

apply(
  'Abstract: contamination claim → ref [1, 2]',
  '(1) public benchmark contamination conflates memorisation with capability,',
  '(1) public benchmark contamination conflates memorisation with capability [1, 2, 3],',
)

apply(
  'Abstract: undefended claim → ref [4, 5]',
  '(2) evaluation against undefended targets — explicitly acknowledged as a limitation in published work by UK AISI and Anthropic — systematically overestimates adversarial capability under real-world conditions.',
  '(2) evaluation against undefended targets — explicitly acknowledged as a limitation in published work by UK AISI [4] and Anthropic [5] — systematically overestimates adversarial capability under real-world conditions.',
)

// ── 2. Add a References section at the end of the markdown source ──────────

const REF_START = '<!-- POLYRANGE_REFERENCES_START -->'
const REF_END   = '<!-- POLYRANGE_REFERENCES_END -->'

const referencesBlock = `${REF_START}
## References

The following sources support the abstract's contamination and undefended-target claims, and the related discussion in the Thesis and Jaggedness sections.

**[1] Sainz, O., Campos, J. A., García-Ferrero, I., Etxaniz, J., Lopez de Lacalle, O., & Agirre, E.** (2024). *NLP Evaluation in trouble: On the Need to Measure LLM Data Contamination for each Benchmark.* Findings of EMNLP 2024. <https://arxiv.org/abs/2310.18018>

> Documents how benchmark test data routinely appears in pretraining corpora and argues that classical evaluation is structurally compromised.

**[2] Magar, I., & Schwartz, R.** (2022). *Data Contamination: From Memorization to Exploitation.* ACL 2022. <https://arxiv.org/abs/2203.08242>

> Distinguishes *memorisation* of contaminated benchmark data from *exploitation* of that memorisation for measured performance gains — the methodological foundation for the "memorisation ≠ capability" claim.

**[3] Coleman, R. (Anthropic)** (2026, March 6). *Eval awareness in Claude Opus 4.6's BrowseComp performance.* <https://www.anthropic.com/engineering/eval-awareness-browsecomp>

> Anthropic's own documentation of three distinct contamination modes on a frontier evaluation: standard contamination from ArXiv/ICLR submissions, eval awareness (Claude Opus 4.6 independently hypothesising it was being tested and decrypting the BrowseComp answer key), and unintended contamination via agent search caching. Includes the direct acknowledgment that *"this report will, itself, likely contribute to the problem"* — the structural argument for moving beyond canary-string detection.

**[4] Folkerts, L., Payne, W., Inman, S., Giavridis, P., Skinner, J., Deverett, S., Aung, J., Zorer, E., Schmatz, M., Ghanem, M., Wilkinson, J., Steer, A., Hong, V., & Wang, J.** (2026). *Measuring AI Agents' Progress on Multi-Step Cyber Attack Scenarios.* arXiv:2603.11214. <https://arxiv.org/abs/2603.11214>

> Cyber-range evaluation of frontier-model multi-step attack capability. The "Limitations" section explicitly enumerates the undefended-target gap: *"No active defenders. Real networks have security teams monitoring for intrusions, responding to alerts, and adapting defences. Our ranges are static, for example our deployment of Elastic Defend was not configured to block or impede attack progress."* Further limitations the authors enumerate include detections not being penalised, vulnerability density variance, and lower artefact density than real environments — each a structural gap PolyRange's defence-tier methodology is designed to bring into the measurement frame.

**[5] Anthropic** (2026). *Claude Mythos Preview System Card.* <https://www-cdn.anthropic.com/08ab9158070959f88f296514c21b7facce6f52bc.pdf>

> Anthropic's frontier-model cyber capability evaluation. § 3.4 "Other external testing" (p. 53) records the explicit acknowledgment that Claude Mythos Preview *"is capable of conducting autonomous end-to-end cyber-attacks on at least small-scale enterprise networks with weak security posture (e.g., no active defences, minimal security monitoring, and slow response capabilities). Note that these ranges lack many features often present in real-world environments such as defensive tooling."* The card also notes (§ 3.1, p. 47) that the frontier-lab evaluation philosophy has *"re-oriented to focus on performance on meaningful, real-world cybersecurity tasks over static benchmarks,"* and (§ 3.3, p. 48) that CTF-style benchmarks have been *"saturated"* by Mythos Preview to the point that Anthropic is questioning whether to continue reporting results on them — a primary-source corroboration of the contamination claim.

---
${REF_END}`

if (plan.includes(REF_START) && plan.includes(REF_END)) {
  const startIdx = plan.indexOf(REF_START)
  const endIdx = plan.indexOf(REF_END, startIdx) + REF_END.length
  plan = plan.slice(0, startIdx) + referencesBlock + plan.slice(endIdx)
  console.log('  + References block (replaced existing)')
  applied++
} else {
  // Insert just before the closing </script> of the markdown source.
  const anchor = '</script>\n\n<script src="https://cdn.jsdelivr.net/npm/mermaid'
  if (plan.includes(anchor)) {
    plan = plan.replace(anchor, '\n' + referencesBlock + '\n</script>\n\n<script src="https://cdn.jsdelivr.net/npm/mermaid')
    console.log('  + References block (inserted at end of markdown)')
    applied++
  } else {
    // Fallback: marked source close
    const fallback = '</script>\n\n<script src="https://cdn.jsdelivr.net/npm/marked'
    if (plan.includes(fallback)) {
      plan = plan.replace(fallback, '\n' + referencesBlock + '\n</script>\n\n<script src="https://cdn.jsdelivr.net/npm/marked')
      console.log('  + References block (inserted at end of markdown, fallback anchor)')
      applied++
    } else {
      console.log('  ! Could not find markdown-source closing tag')
      missing++
    }
  }
}

await fs.writeFile(PLAN_PATH, plan)

console.log('━'.repeat(72))
console.log(`  ${applied} applied  ·  ${skipped} already in place  ·  ${missing} anchors missing`)
console.log()
if (missing === 0) console.log('  open plan.html')
