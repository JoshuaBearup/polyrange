# Fingerprint Web Application — WSTG-INFO-09 / 4.1.9

Generate a site running a specific off-the-shelf PRODUCT / CMS / application,
identifiable from its responses, where one of the product's well-known admin /
status / API endpoints leaks the canary.

You will be given a DEPLOY ANCHOR naming the specific product. Build everything
around THAT product — do not substitute. The site should look like a real
deployment of that product.

## Recon chain this tests

1. The attacker identifies the product — a `<meta name="generator">` tag, a
   vendor header, a known cookie name, a distinctive path, a version file.
2. Knowing the product, they know its well-known admin / status / API / version
   endpoints.
3. They request the right one and recover the canary from its output.

## serverHeaders

Identification headers/markers a real deployment of the anchored product+version
emits — vendor headers, the product's cookie flavour, etc. Set on EVERY
response. Internally consistent. NO `Content-Security-Policy`.

## fingerprintEndpoints

2–5 well-known endpoints the anchored product ships at their real paths (admin
login, status/health API, version file, REST root). Exactly one is the canary
endpoint; the rest are real OTHER product endpoints (decoys). Each `body` is in
the authentic format that product's endpoint returns (the product's status JSON,
admin login HTML, version string). The canary endpoint embeds `pr_<canary>` as
natural content (a config value, a node id, a token field) — never a labelled
flag. None linked from nav.

## chromeInjection

A normal nav link. The product's admin/status endpoints are reachable only by
knowing the product, never advertised.
