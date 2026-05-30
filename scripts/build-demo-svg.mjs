// Generates assets/demo-monitor.svg — a literal 1:1 reproduction of the
// polyrange.mjs live monitor terminal output. Five key frames are rendered
// using the same dashboard primitives the real monitor uses (box-drawing,
// block-char bars, Braille spinner), then cross-faded in SMIL over a
// 16-second loop. Each frame is exactly what the terminal would print at
// that point in a real eval — no SVG primitives substituting for terminal
// characters.
//
// Output is GitHub-renderable as a single SVG via <img> tag.

import fs from 'node:fs/promises'
import path from 'node:path'
import {
  boxTop, boxBottom, boxLine, boxBlank, boxDivider,
  padRightVisible, padLeftVisible, progressBar, formatDuration, wilson95,
} from '../lib/dashboard.mjs'

const OUT = path.join(process.cwd(), 'assets', 'demo-monitor.svg')

// ── Frame definitions ─────────────────────────────────────────────────────

const TOTAL = 138
const T0_TOTAL = 84
const T1_TOTAL = 54
const DUR = 16
const SPINNER = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']

const FRAMES = [
  { t: 0.0,  solved: 0,  working: 0,  agentMs: 0,        showAt: 1.0 },
  { t: 2.0,  solved: 8,  working: 6,  agentMs: 78_000,   showAt: 3.0 },
  { t: 5.5,  solved: 24, working: 5,  agentMs: 245_000,  showAt: 3.5 },
  { t: 9.5,  solved: 41, working: 3,  agentMs: 612_000,  showAt: 3.5 },
  { t: 13.5, solved: 47, working: 2,  agentMs: 752_000,  showAt: 2.5 },
]

const RECENT_SOLVES = [
  { tier: 'T0', cls: 'wstg-sqli-4.7.5.4',       dur: '2m 14s', reqs: 38, ago: 'just now', showFrom: 1 },
  { tier: 'T1', cls: 'wstg-lfi-4.7.11.1',       dur: '3m 11s', reqs: 48, ago: '18s ago',  showFrom: 2 },
  { tier: 'T0', cls: 'wstg-xss-4.7.1',          dur: '1m 48s', reqs: 24, ago: '42s ago',  showFrom: 2 },
  { tier: 'T0', cls: 'wstg-idor-4.5.4',         dur: '1m 11s', reqs: 14, ago: '1m ago',   showFrom: 3 },
  { tier: 'T1', cls: 'wstg-jwt-4.6.10',         dur: '3m 41s', reqs: 54, ago: '3m ago',   showFrom: 4 },
]

// ── Render one frame as the exact terminal output ──────────────────────────

function renderFrameLines(f, frameIdx) {
  const lines = []
  const idle = TOTAL - f.solved - f.working
  const solvedPct = f.solved > 0 ? ((f.solved / TOTAL) * 100).toFixed(1) : '0.0'
  const tier0Solved = Math.round(f.solved * 0.66)
  const tier1Solved = f.solved - tier0Solved

  // Compute aggregates that depend on solved count
  let solveRate = '—'
  let solveRateCi = ''
  let medianTime = '—'
  let medianReqs = '—'
  let defenceGap = '—'
  if (f.solved >= 5) {
    solveRate = (0.500 + Math.random() * 0.2).toFixed(3)
    // Use a fixed plausible value
    solveRate = f.solved >= 40 ? '0.681' : f.solved >= 20 ? '0.550' : '0.400'
    const [lo, hi] = wilson95(f.solved, f.solved + 22)
    solveRateCi = `[${lo.toFixed(3)}, ${hi.toFixed(3)}]`
    medianTime = '1m 52s'
    medianReqs = '27'
    defenceGap = f.solved >= 40 ? '+0.07' : f.solved >= 20 ? '+0.04' : '—'
  }

  // ── Header line with spinner placeholder (replaced inline in SVG later) ─
  const elapsedStr = formatDuration(f.agentMs) || '0s'
  const headerCore = `  opus-4-8  2026-05-30-opus  ·  agent ${padRightVisible(elapsedStr, 8)} ·  poll in 3s`
  // We will inject a literal "%SPIN%" placeholder where the spinner glyph goes;
  // it gets substituted with overlapping spinner <tspan>s in the SVG render step.
  lines.push(boxTop(`Monitor %SPIN%${headerCore}`))
  lines.push(boxBlank())

  // ── Three progress bars (literal block chars) ─
  const solvedBar  = progressBar(f.solved,  TOTAL, { width: 36, label: `${String(f.solved).padStart(2)} / ${TOTAL}    ${solvedPct}%` })
  const workingBar = progressBar(f.working, TOTAL, { width: 36, label: `${String(f.working).padStart(2)} / ${TOTAL}` })
  const idleBar    = progressBar(idle,      TOTAL, { width: 36, label: `${String(idle).padStart(2)} / ${TOTAL}` })
  lines.push(boxLine(`  Solved   ${solvedBar}`))
  lines.push(boxLine(`  Working  ${workingBar}`))
  lines.push(boxLine(`  Idle     ${idleBar}`))
  lines.push(boxBlank())

  // ── Aggregate panel ─
  lines.push(boxDivider('Aggregate (running)'))
  lines.push(boxLine(`  Solve rate     ${padRightVisible(solveRate, 8)}${solveRateCi}`))
  lines.push(boxLine(`  Median time    ${medianTime}`))
  lines.push(boxLine(`  Median reqs    ${medianReqs}`))
  lines.push(boxLine(`  T0 solved      ${tier0Solved}/${T0_TOTAL}`))
  lines.push(boxLine(`  T1 solved      ${tier1Solved}/${T1_TOTAL}`))
  lines.push(boxLine(`  Defence gap    ${defenceGap}`))
  lines.push(boxBlank())

  // ── Recent solves panel ─
  lines.push(boxDivider('Recent solves'))
  const visible = RECENT_SOLVES.filter(r => r.showFrom <= frameIdx)
  if (visible.length === 0) {
    lines.push(boxLine('  (waiting for first solve)'))
  } else {
    for (const r of visible.slice(0, 4)) {
      const cls = padRightVisible(r.cls, 32)
      const dur = padRightVisible(r.dur, 9)
      const reqs = padRightVisible(`${r.reqs} req`, 9)
      lines.push(boxLine(`  ok  ${r.tier}  ${cls}${dur}${reqs}${r.ago}`))
    }
    // Pad to 4 lines so panel height is stable across frames
    for (let i = visible.length; i < 4; i++) lines.push(boxLine(''))
  }
  lines.push(boxBlank())

  // ── Keys footer ─
  lines.push(boxDivider('Keys'))
  lines.push(boxLine('  ^C  Finalise   ^R  Refresh   ^Q  Abort'))
  lines.push(boxBlank())
  lines.push(boxBottom())

  return lines
}

// ── Convert terminal text to SVG <text>/<tspan> for one frame ──────────────

function escapeXml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

function renderFrameSVG(f, frameIdx, lineH, charW, x0, y0) {
  const lines = renderFrameLines(f, frameIdx)

  // Cross-fade opacity for this frame.
  // Each frame becomes visible at its t, stays visible until next frame's t,
  // fades out over 0.4s into the next frame.
  const fade = 0.4
  const myT = FRAMES[frameIdx].t
  const nextT = FRAMES[frameIdx + 1]?.t ?? DUR
  const times = []
  const values = []
  if (frameIdx === 0) {
    times.push(0, fade / DUR, (nextT - fade) / DUR, nextT / DUR, 1)
    values.push(1, 1, 1, 0, 0)
  } else {
    times.push(0, (myT - fade) / DUR, myT / DUR, (nextT - fade) / DUR, nextT / DUR, 1)
    values.push(0, 0, 1, 1, 0, 0)
  }
  const anim = `<animate attributeName="opacity" values="${values.join(';')}" keyTimes="${times.join(';')}" dur="${DUR}s" repeatCount="indefinite"/>`

  // Build the lines as <tspan>s within a single <text> element so the
  // browser handles vertical line-stacking via x/dy.
  let frame = `<g opacity="${frameIdx === 0 ? 1 : 0}">${anim}\n`
  frame += `  <text x="${x0}" y="${y0}" font-family="'Geist Mono', ui-monospace, SFMono-Regular, Menlo, monospace" font-size="12.5" xml:space="preserve" fill="#1c1917">\n`
  lines.forEach((line, i) => {
    // The %SPIN% placeholder needs special handling: render the surrounding
    // text but leave a 1-char gap where the animated spinner overlay will sit.
    if (line.includes('%SPIN%')) {
      const [before, after] = line.split('%SPIN%')
      frame += `    <tspan x="${x0}" dy="${i === 0 ? '0' : lineH + 'px'}">${escapeXml(before)} ${escapeXml(after)}</tspan>\n`
    } else {
      frame += `    <tspan x="${x0}" dy="${i === 0 ? '0' : lineH + 'px'}">${escapeXml(line)}</tspan>\n`
    }
  })
  frame += `  </text>\n`
  frame += `</g>\n`
  return frame
}

// ── Spinner overlay (10 glyphs, only one visible at a time, cycles 1Hz) ────

function renderSpinnerOverlay(x, y) {
  // The spinner sits at the position of "Monitor [SPIN]" in the header,
  // 1 char past the start of the header content. Compute its x position.
  let s = `<g>\n`
  SPINNER.forEach((glyph, i) => {
    // 10-step cycle, each visible for 1/10s
    const total = 10
    const times = []
    const values = []
    for (let k = 0; k <= total; k++) {
      times.push((k / total).toFixed(3))
      values.push(k === i ? 1 : 0)
    }
    s += `  <text x="${x}" y="${y}" font-family="'Geist Mono', ui-monospace, SFMono-Regular, Menlo, monospace" font-size="12.5" font-weight="700" fill="#9580FF" opacity="${i === 0 ? 1 : 0}">${glyph}<animate attributeName="opacity" values="${values.join(';')}" keyTimes="${times.join(';')}" dur="1s" repeatCount="indefinite"/></text>\n`
  })
  s += `</g>\n`
  return s
}

// ── Build the full SVG ─────────────────────────────────────────────────────

// Geist Mono / ui-monospace at 12.5px:
// - char width ≈ 7.6px
// - line height ≈ 18px
const CHAR_W = 7.6
const LINE_H = 18
const PAD = 18

// Frame dimensions: 76 chars wide, ~24 lines tall
const FRAME_COLS = 76
const FRAME_ROWS = 24
const FRAME_W = FRAME_COLS * CHAR_W
const FRAME_H = FRAME_ROWS * LINE_H

const W = Math.ceil(FRAME_W + PAD * 2)
const H = Math.ceil(FRAME_H + PAD * 2)

const X0 = PAD
const Y0 = PAD + LINE_H * 0.85   // SVG text y is the baseline; offset down

// Spinner position: 2 chars into the box title "╭─ Monitor [SPIN]"
// Header is at y0 (first line). Spinner sits at column ~11 (after "╭─ Monitor ")
const SPINNER_X = X0 + 11 * CHAR_W
const SPINNER_Y = Y0

let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" preserveAspectRatio="xMidYMid meet">
  <rect x="0" y="0" width="${W}" height="${H}" fill="#fafaf9"/>
  <rect x="6" y="6" width="${W - 12}" height="${H - 12}" fill="#ffffff" stroke="#e7e5e4" rx="8"/>
  <rect x="6" y="6" width="${W - 12}" height="3" fill="#9580FF" rx="2"/>
`

// Render each frame
FRAMES.forEach((f, i) => {
  svg += renderFrameSVG(f, i, LINE_H, CHAR_W, X0, Y0)
})

// Spinner overlay (always visible, cycles 1Hz)
svg += renderSpinnerOverlay(SPINNER_X, SPINNER_Y)

svg += `</svg>
`

await fs.mkdir(path.dirname(OUT), { recursive: true })
await fs.writeFile(OUT, svg)
console.log(`Wrote ${OUT}`)
console.log(`  Size: ${(svg.length / 1024).toFixed(1)} KB`)
console.log(`  Dimensions: ${W} × ${H}`)
console.log(`  Frames: ${FRAMES.length}`)
console.log(`  Loop: ${DUR}s`)
console.log()
console.log('  Embed in README via:')
console.log('    ![PolyRange live monitor](assets/demo-monitor.svg)')
