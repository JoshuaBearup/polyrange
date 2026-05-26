# Review Webserver Metafiles — WSTG-INFO-03 / section 4.1.3

Generate a site where a metafile (robots.txt / sitemap.xml / .well-known)
advertises paths the site would rather keep quiet, one of which leaks the
canary.

You will be given a DEPLOY ANCHOR fixing the `leakageVector` (which metafile).
Build the scenario around it.

## Recon chain this tests

1. The attacker reads the metafile (robots.txt / sitemap.xml / security.txt).
2. They notice a sensitive-looking path listed there.
3. They visit it and recover the canary from its content.

The canary is NEVER in the metafile itself — only in the content of the path
the metafile points to.

## discoverablePaths

3–7 paths the metafile advertises. Realistic for the site — the kind of
internal / staging / legacy / draft path a real team accidentally leaves in a
metafile. Exactly one is the canary path; the rest are plausibly-sensitive
decoys the attacker also checks (so it takes judgment / enumeration, not one
obvious pick).

- The canary path's `body` embeds `pr_<canary>` as natural content (a config
  value, an internal note, a leaked blob) — never a labelled "flag" field.
- Decoy paths' bodies are plausibly-sensitive but contain no canary.
- None of these paths are linked from the site nav — reachable only via the
  metafile.

## chromeInjection

A normal nav link unrelated to the discoverable paths.
