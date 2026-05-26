# PolyRange — remaining-class build sequencing

NOT a "blocked" list — Docker runs almost everything. Classes are grouped by
what they need before they're buildable. Only a tiny set is truly impossible.

## Buildable NOW — SAFE (no real exec, no outbound egress; PG/stateless only)
- 4.7.2 Stored XSS (PG: store + render)
- 4.7.20 Mass assignment (PG: JSON body sets unexpected field)
- 4.5.2 Authz bypass / 4.5.3 Privilege escalation (PG, IDOR-variants)
- 4.7.4 HTTP parameter pollution (stateless)
- 4.7.15 HTTP response splitting (stateless, CRLF)
- 4.7.17 Host header injection (stateless, reflected host)
- 4.7.21 CSV injection (stateless, export formula)
- 4.8.1 Improper error handling / 4.8.2 stack traces (force errors → leak)

## Buildable but needs a SAFETY decision first (real exec / outbound fetch on live infra)
- 4.7.12 OS command injection — real child_process.exec → the model runs
  arbitrary commands in our Fly container (egress + RCE on our infra). Needs
  egress lockdown / container hardening / a sandboxed exec decision.
- 4.7.11 Code injection — real eval/vm; same RCE-on-our-infra concern.
- 4.7.19 SSRF — real fetch of a model-supplied URL → can hit arbitrary hosts
  from our infra (the exact pivoting risk). Needs egress allow-listing so the
  fetch can only reach the in-container internal target, never the internet.
  (Mechanism is easy; the safety control is the decision.)
- 4.7.4 HTTP parameter pollution (stateless)
- 4.7.15 HTTP response splitting (stateless, CRLF)
- 4.7.17 Host header injection (stateless, reflected host)
- 4.7.21 CSV injection (stateless, export formula)
- 4.5.2 Authz bypass / 4.5.3 Privilege escalation (PG, IDOR-variants)
- 4.8.1 Improper error handling / 4.8.2 Stack traces (force errors → leak)
- 4.12.2/.3/.4 API BOLA / excess-data / BFLA (PG, JSON-API IDOR variants)
- 4.3.x identity / 4.4.x auth / 4.6.x session (PG + signup; each needs a chosen
  exploit→canary chain, but no new infra)

## Needs a one-time CLUSTER/SIDECAR Dockerfile first (then buildable — Docker supports all)
- 4.7.5.1/.2/.3 SQLi Oracle / MySQL / MSSQL — one DB image per dialect
- 4.7.5.6 NoSQL injection — Mongo image
- 4.7.6 LDAP injection — OpenLDAP sidecar
- 4.7.8 SSI injection — SSI-enabled server image
- 4.7.10 IMAP/SMTP injection — mail (Postfix/Dovecot) sidecar
- 4.7.18 SSTI — template-engine image per language (Jinja/Twig/ERB/Handlebars)
- 4.7.16 HTTP request smuggling + 4.2.13 Path confusion — reverse-proxy (nginx/HAProxy) in front
- 4.9.1 Weak TLS — TLS-misconfigured container
- 4.11.10 WebSockets — ws server
- 4.12.99 GraphQL — Apollo server

## Needs a TOOLING build first (Playwright in the deploy validator) — then buildable
- 4.11.1/.1.1 DOM XSS, 4.11.2 JS exec, 4.11.5 CSS injection, 4.11.9 clickjacking,
  4.11.11 web messaging, 4.11.12 browser storage, 4.11.14 reverse tabnabbing,
  4.11.15 client-side template injection, 4.4.6 browser cache
  (all need a real browser to confirm exploit success)

## Needs a design decision (the exploit→canary chain choice), then buildable now
- 4.2.6 HTTP verb tampering, 4.2.7/4.2.12/4.2.14 header policy (HSTS/CSP/headers),
  4.2.8 crossdomain, 4.5.5 OAuth, 4.6.5 CSRF, 4.6.10 JWT, 4.9.2 padding oracle,
  4.9.4 weak crypto, 4.10.x business logic

## Genuinely out of scope (the only true wall)
- 4.1.1 search engine (external engines we don't control)
- 4.2.1 network config (network layer)
- 4.2.10 subdomain takeover (DNS layer)
- 4.2.9 file permission (OS-level perms, not externally testable)
- 4.7.13 format string (C/C++ only) · 4.11.8 cross-site flashing (Flash EOL)
