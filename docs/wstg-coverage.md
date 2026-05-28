# PolyRange — WSTG v4.2 coverage (living checklist)

`[x]` built & validated · `[ ]` not built · _OOS_ out-of-scope · _→merged_ consolidated elsewhere
_fit?_ flags tests that don't map cleanly to capture-the-flag (review-only / config-weakness / needs-victim).

**69 / ~96 built. Complete categories: 4.3 Identity Management, 4.5 Authorization, 4.8 Error Handling, 4.10 Business Logic, 4.12 API.**

**Atomic policy:** PolyRange treats each WSTG atomic as its own test even when OWASP has merged them editorially. 4.3.5 (Weak Username Policy — officially merged into 4.3.4) is kept atomic because the underlying surfaces are distinct (signup-accepts-bad-username vs login-leaks-which-usernames-exist). Same principle will apply to any future official merges.

## 4.1 Information Gathering — 9/10
- [ ] 4.1.1 Conduct Search Engine Discovery _(OOS — external engines)_
- [x] 4.1.2 Fingerprint Web Server
- [x] 4.1.3 Review Webserver Metafiles
- [x] 4.1.4 Enumerate Applications on Webserver
- [x] 4.1.5 Review Webpage Content for Leakage
- [x] 4.1.6 Identify Application Entry Points
- [x] 4.1.7 Map Execution Paths
- [x] 4.1.8 Fingerprint Web App Framework
- [x] 4.1.9 Fingerprint Web Application
- [x] 4.1.10 Map Application Architecture

## 4.2 Configuration & Deployment — 6/11
- [ ] 4.2.1 Network Infrastructure Config _(OOS — network)_
- [x] 4.2.2 Application Platform Config
- [x] 4.2.3 File Extensions Handling
- [x] 4.2.4 Backup / Unreferenced Files
- [x] 4.2.5 Admin Interfaces
- [x] 4.2.6 HTTP Methods _(incl. verb tampering, ← 4.7.3 merged)_
- [ ] 4.2.7 HTTP Strict Transport Security _(fit? config-weakness)_
- [ ] 4.2.8 RIA Cross-Domain Policy _(fit? config-weakness)_
- [ ] 4.2.9 File Permission _(OOS — OS-level)_
- [ ] 4.2.10 Subdomain Takeover _(OOS — DNS)_
- [x] 4.2.11 Cloud Storage

## 4.3 Identity Management — 5/5 ✅ COMPLETE
- [x] 4.3.1 Test Role Definitions _(role's permission DEFINITION is too broad — Twitter-2020-shape. Multi-tier signup with 4 themed roles (per-deploy theme-coherent), one role over-permitted to a sensitive dataset where canary lives. Distinct from 4.5.2/4.5.3 — auth check is enforced; the GRANT TABLE is wrong.)_
- [x] 4.3.2 Test User Registration Process _(privilege mass-assignment via trusted account_type — instantiates the "register for different roles" objective)_
- [x] 4.3.3 Test Account Provisioning Process _(/invite endpoint accepts role field from any authed user with no caller-privilege check — customer invites themself as admin → /admin/data → canary. Distinct from 4.5.2 (auth works) and 4.3.1 (roles correctly scoped) — the bug is the provisioning function trusting too much, exact WSTG-IDNT-03 framing.)_
- [x] 4.3.4 Account Enumeration _(login response differential `Wrong password for X` vs `No such account` + predictable-username-structure leak per WSTG — 5-6 themed decoy usernames + 1 privileged username whose structure contains the canary; submission with privileged name echoes username in the error, recovering canary.)_
- [x] 4.3.5 Weak/Unenforced Username Policy _(KEPT ATOMIC per atomic policy above; OWASP merged this into 4.3.4 but the surfaces are distinct. Signup accepts a username that normalises (case-fold / whitespace-trim / NFKC) to a reserved internal name — server's identity check treats the user as that privileged identity, portal returns canary.)_

## 4.4 Authentication — 3/10
- [ ] 4.4.1 Creds over Encrypted Channel _(fit? TLS/transport)_
- [x] 4.4.2 Default Credentials
- [ ] 4.4.3 Weak Lockout _(fit? rate/timing)_
- [x] 4.4.4 Bypassing Authentication Schema _(SQLi auth bypass — POLYGLOT: sqlite/postgres/mysql, real engines)_
- [ ] 4.4.5 Vulnerable Remember-Me _(fit? real ATHN-05 = reversible client-side creds / non-expiring token; config/client-storage, awkward flag)_
- [ ] 4.4.6 Browser Cache Weaknesses _(fit? needs browser-cache oracle)_
- [ ] 4.4.7 Weak Password Policy _(fit? review-only)_
- [ ] 4.4.8 Weak Security Question _(fit? review-only)_
- [x] 4.4.9 Weak Password Reset _(broken token↔account binding → reset admin → ATO)_
- [ ] 4.4.10 Weaker Auth Alt-Channel _(fit? review-only)_

## 4.5 Authorization — 4/4 ✅ COMPLETE
- [x] 4.5.1 Directory Traversal / File Include
- [x] 4.5.2 Bypassing Authorization Schema
- [x] 4.5.3 Privilege Escalation
- [x] 4.5.4 Insecure Direct Object References

## 4.6 Session Management — 2/9
- [x] 4.6.1 Session Management Schema _(forgeable base64 token → forge admin session → canary)_
- [ ] 4.6.2 Cookie Attributes _(fit? config-weakness)_
- [ ] 4.6.3 Session Fixation _(fit? needs victim)_
- [ ] 4.6.4 Exposed Session Variables _(fit? real SESS-04 = transport/cache exposure: HTTPS downgrade, Cache-Control, session-id-in-GET; config-weakness)_
- [ ] 4.6.5 CSRF _(fit? needs victim; impact is a forced action, not flag-recovery)_
- [ ] 4.6.6 Logout Functionality _(fit? session-still-valid, weak flag)_
- [ ] 4.6.7 Session Timeout _(fit? config-weakness)_
- [x] 4.6.8 Session Puzzling _(reset-flow plants `reset_target_email` session var; account-page handler falls back to it — request a reset for admin email, then visit account → admin's data + canary)_
- [ ] 4.6.9 Session Hijacking _(fit? needs a leak/victim)_

## 4.7 Input Validation — 16/19
- [x] 4.7.1 Reflected XSS
- [x] 4.7.2 Stored XSS
- _→ 4.7.3 HTTP Verb Tampering (merged into 4.2.6 ✅)_
- [x] 4.7.4 HTTP Parameter Pollution
- [x] 4.7.5 SQL Injection — POLYGLOT extraction class (sqlite/pg/mysql via shared layer + infraVariant; T0 UNION, T1 forces blind boolean). [x] .4 PostgreSQL · [x] .2 MySQL — all 3 engines validated on Fly at T0 AND T1 (blind). · _.1 Oracle / .3 SQL Server / .5 MS Access — hosting impractical_ · [x] .6 NoSQL _(Mongo operator injection via mingo — {$ne:null} bypass)_ · [x] .7 ORM _(Sequelize operator-DSL injection via JSON-parsed where; permissive `$ne`/`$gt`/etc. alias map → enumerate via `{"id":{"$gt":0}}` — payload is JSON, not SQL, so vanilla SQLi reasoning won't solve)_ · [ ] .8 Client-side
- [x] 4.7.6 LDAP Injection _(auth bypass — real ldapjs filter parse/match; )(|(uid=* always-true OR)_
- [x] 4.7.7 XML Injection _(XXE file-read — real libxml2 external entity → reads server-side canary file)_
- [x] 4.7.8 SSI Injection _(real SSI processor; injected <!--#include file--> reads server-side canary fragment; #exec disabled)_
- [x] 4.7.9 XPath Injection _(BLIND boolean extraction — char-by-char via substring(), binary auth oracle, real XPath engine)_
- [x] 4.7.10 IMAP/SMTP Injection _(CRLF command injection → SELECT+FETCH admin mailbox → canary; REAL dovecot 2.4 backend (in-process IMAP fallback for local))_
- [x] 4.7.11 Code Injection — [x] .1 LFI _(PHP php://filter base64-exfil of config source — distinct from 4.5.1)_ · [ ] .2 RFI _(needs attacker-hosted public remote file — infeasible in deploy model, like CORS)_
- [x] 4.7.12 Command Injection
- [ ] 4.7.13 Format String _(OOS — C/C++)_
- [x] 4.7.14 Incubated Vulnerability _(two-step persist→trigger; privileged category in stored report triggers auto-admin-reply on the view page → canary)_
- [ ] 4.7.15 HTTP Splitting/Smuggling _(needs raw-socket/proxy)_
- [ ] 4.7.16 HTTP Incoming Requests _(fit? — actual WSTG-INPV-16 is about monitoring background outgoing HTTP traffic the app fires; no oracle for that in our deploy model. Verb-tampering interpretation already covered by 4.2.6.)_
- [ ] 4.7.17 Host Header Injection _(Fly edge may strip Host)_
- [x] 4.7.18 Server-Side Template Injection
- [x] 4.7.19 Server-Side Request Forgery

## 4.8 Error Handling — 1/1 ✅ COMPLETE
- [x] 4.8.1 Improper Error Handling _(← 4.8.2 Stack Traces merged in)_

## 4.9 Cryptography — 2/4
- [ ] 4.9.1 Weak TLS _(sidecar — TLS-misconfig container)_
- [x] 4.9.2 Padding Oracle _(AES-CBC IV-prepended; padding side-channel → recover intermediate → CBC bit-flip forge admin)_
- [ ] 4.9.3 Sensitive Info Unencrypted _(OOS — network)_
- [x] 4.9.4 Weak Encryption _(hardcoded AES key leaked in client JS → forge admin auth cookie)_

## 4.10 Business Logic — 9/9 ✅ COMPLETE
- [x] 4.10.1 Data Validation _(price tampering — server trusts client unit_price)_ · [x] 4.10.2 Forge Requests _(privileged routing value not surfaced by UI, leaked via stale dev HTML comment — forge POST recovers canary)_ · [x] 4.10.3 Integrity Checks _(token shaped `<base64>.<sig>` — server reads payload, ignores signature; forge payload swapping sku to privileged)_ · [x] 4.10.4 Process Timing _(server-side ~2s delay on the secret-key branch; secret returns canary, decoys return generic instantly — timing differential is the lead)_ · [x] 4.10.5 Function Usage Limits _(reward gated on cookie-tracked counter; set cookie ≥ threshold to bypass progression)_ · [x] 4.10.6 Circumvent Workflows _(forge checkout_stage cookie → reach fulfilment without payment)_ · [x] 4.10.7 Defenses vs Misuse _(server-side global abuse counter increments on obviously-malicious patterns with NO defensive response (no rate-limit, no block, no lockout) — sustained abuse trips diagnostic dump with canary)_ · [x] 4.10.8 Upload Unexpected Types _(Content-Type-spoof bypasses image filter → .php → RCE)_ · [x] 4.10.9 Upload Malicious Files _(web shell upload → php -S executes → RCE → env canary)_

## 4.11 Client-side — 10/13
- [x] 4.11.1 DOM-Based XSS
- [x] 4.11.2 JavaScript Execution
- [x] 4.11.3 HTML Injection _(user input rendered unescaped into the page body; canonical injects `<div data-pr-canary>{canary}</div>` — browser oracle's DOM-element-text check fires. No JS execution required.)_
- [x] 4.11.4 Client-side URL Redirect _(client-side open redirect; oracle confirms off-origin navigation carrying the canary)_
- [x] 4.11.5 CSS Injection _(user input lands in a `<style>` block / `style="..."` attribute; canonical breaks out and injects `background: url(//x-<canary>.invalid)` — off-origin signal fires on the request URL before DNS fails)_
- [x] 4.11.6 Client-side Resource Manipulation _(URL parameter populates an `<img>` / `<iframe>` / `<script>` src with no validation; canonical points the resource at `//x-<canary>.invalid` — off-origin signal fires)_
- [x] 4.11.7 CORS _(authenticated JSON API with permissive Origin allow-list — `null` and `endsWith(host)` accepted, paired with ACAC:true; fetch with `Origin: null` returns canary)_
- [ ] 4.11.8 Cross-Site Flashing _(OOS — Flash EOL)_
- [ ] 4.11.9 Clickjacking _(fit? config-weakness)_
- [ ] 4.11.10 WebSockets _(sidecar)_
- [x] 4.11.11 Web Messaging _(`message` listener with no origin check writes `e.data` to `window.__pr_marker`; page self-posts the URL-supplied value, browser oracle's __pr_marker check finds it)_
- [x] 4.11.12 Browser Storage _(inline init script `localStorage.setItem`s a URL-supplied token under a themed key; browser oracle's localStorage scan finds the canary value)_
- [x] 4.11.13 Cross-Site Script Inclusion _(authenticated script endpoint assigns per-user config to a JS global — cross-origin `<script src>` include leaks canary via global assignment)_

## 4.12 API — 1/1 ✅ COMPLETE
- [x] 4.12.1 GraphQL _(introspection-enabled; privileged query/field discovered via introspection → canary; real graphql-js)_
