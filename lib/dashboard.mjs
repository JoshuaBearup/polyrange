// Dashboard primitives — box-drawing render helpers shared by all phase
// screens. Keep these pure (string in, string out) so the screens compose
// trivially and the output is identical when piped to a file.

const dim = (s) => `\x1b[2m${s}\x1b[0m`
const bold = (s) => `\x1b[1m${s}\x1b[0m`
const reset = '\x1b[0m'
const green = (s) => `\x1b[32m${s}\x1b[0m`
const red = (s) => `\x1b[31m${s}\x1b[0m`
const cyan = (s) => `\x1b[36m${s}\x1b[0m`
const yellow = (s) => `\x1b[33m${s}\x1b[0m`

export const colors = { dim, bold, green, red, cyan, yellow, reset }

// Visible (unstyled) width — ignores ANSI escape sequences so box math is
// accurate when content carries color codes.
export function visibleWidth(s) {
  return String(s).replace(/\x1b\[[0-9;]*m/g, '').length
}

function padRightVisible(s, width) {
  const pad = Math.max(0, width - visibleWidth(s))
  return s + ' '.repeat(pad)
}

function padLeftVisible(s, width) {
  const pad = Math.max(0, width - visibleWidth(s))
  return ' '.repeat(pad) + s
}

export { padRightVisible, padLeftVisible }

// Outer box width (including borders). 76 is wide enough to host the per-
// section tables and narrow enough to fit in standard terminal panes.
export const BOX_WIDTH = 76

export function boxTop(title = '', width = BOX_WIDTH) {
  const inner = width - 2
  if (!title) return '╭' + '─'.repeat(inner) + '╮'
  const decorated = ` ${title} `
  const remaining = inner - visibleWidth(decorated) - 1
  return '╭─' + decorated + '─'.repeat(Math.max(0, remaining)) + '╮'
}

export function boxBottom(width = BOX_WIDTH) {
  return '╰' + '─'.repeat(width - 2) + '╯'
}

export function boxLine(content = '', width = BOX_WIDTH) {
  const inner = width - 4 // two border chars + one pad each side
  const body = padRightVisible(' ' + content, inner + 1)
  return '│' + body + ' │'
}

export function boxBlank(width = BOX_WIDTH) {
  return '│' + ' '.repeat(width - 2) + '│'
}

export function boxDivider(label = '', width = BOX_WIDTH) {
  const inner = width - 2
  if (!label) return '├' + '─'.repeat(inner) + '┤'
  const decorated = ` ${label} `
  const remaining = inner - visibleWidth(decorated) - 1
  return '├─' + decorated + '─'.repeat(Math.max(0, remaining)) + '┤'
}

// A two-column split row inside the box. Left and right cells get equal
// width minus 1 for the centre separator.
export function boxSplit(left, right, width = BOX_WIDTH) {
  const inner = width - 4
  const half = Math.floor(inner / 2)
  const leftCell = padRightVisible(' ' + left, half)
  const rightCell = padRightVisible(' ' + right, inner - half)
  return '│' + leftCell + '│' + rightCell + ' │'
}

export function boxSplitDivider(width = BOX_WIDTH, label = '') {
  const inner = width - 2
  const half = Math.floor((inner - 2) / 2)
  if (!label) {
    return '├' + '─'.repeat(half) + '┼' + '─'.repeat(inner - half - 1) + '┤'
  }
  return '├' + '─'.repeat(half) + '┴' + '─'.repeat(inner - half - 1) + '┤'
}

// Plain progress bar. Returns a string like "████████░░░░░░░░░░  47 / 170".
export function progressBar(value, max, opts = {}) {
  const width = opts.width || 30
  const ratio = max > 0 ? Math.min(1, Math.max(0, value / max)) : 0
  const filled = Math.round(ratio * width)
  const bar = '█'.repeat(filled) + '░'.repeat(width - filled)
  const label = opts.label !== undefined ? '  ' + opts.label : `  ${value} / ${max}`
  return bar + label
}

// Format helpers — duration, ratios, money.
export function formatDuration(ms) {
  if (ms == null || Number.isNaN(ms)) return '?'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  const min = Math.floor(ms / 60_000)
  const sec = Math.floor((ms % 60_000) / 1000)
  return `${min}m${sec.toString().padStart(2, '0')}s`
}

export function formatDollars(n) {
  if (n == null || Number.isNaN(n)) return '$?'
  return '$' + Number(n).toFixed(2)
}

// 95% Wilson interval for a binomial proportion.
export function wilson95(successes, n) {
  if (n === 0) return [0, 0]
  const z = 1.96
  const p = successes / n
  const denom = 1 + (z * z) / n
  const centre = (p + (z * z) / (2 * n)) / denom
  const half = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n)) / denom
  return [Math.max(0, centre - half), Math.min(1, centre + half)]
}

export function formatProportion(p) {
  if (p == null || Number.isNaN(p)) return '?'
  return p.toFixed(3)
}

// Render a sparkline of per-bucket counts. Returns a multi-line block sized
// to `height` rows. Useful for showing solve-rate over time.
export function sparkline(values, opts = {}) {
  const height = opts.height || 4
  const blocks = ['░', '▂', '▄', '▆', '█']
  if (values.length === 0) return Array(height).fill('')
  const max = Math.max(1, ...values)
  const rows = []
  for (let h = height; h >= 1; h--) {
    let row = ''
    for (const v of values) {
      const filledRows = (v / max) * height
      const cellLevel = Math.max(0, Math.min(blocks.length - 1,
        Math.round((filledRows - (h - 1)) * (blocks.length - 1))))
      row += cellLevel > 0 ? blocks[cellLevel] : ' '
    }
    rows.push(row)
  }
  return rows
}

// ANSI cursor-control helpers for screens that update in place (monitor).
export const cursor = {
  hide: '\x1b[?25l',
  show: '\x1b[?25h',
  home: '\x1b[H',
  clearScreen: '\x1b[2J\x1b[H',
  clearBelow: '\x1b[J',
  saveTo: (line, col = 1) => `\x1b[${line};${col}H`,
}
