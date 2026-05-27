# PolyRange — WSTG v4.2 coverage (living checklist)

`[x]` built & validated · `[ ]` not built · _OOS_ out-of-scope · _→merged_ consolidated elsewhere
_fit?_ flags tests that don't map cleanly to capture-the-flag (review-only / config-weakness / needs-victim).

**39 / ~96 built. Complete categories: 4.5 Authorization, 4.8 Error Handling.**

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

## 4.3 Identity Management — 1/5
- [ ] 4.3.1 Test Role Definitions _(fit? review-only)_
- [x] 4.3.2 Test User Registration Process _(privilege mass-assignment via trusted account_type — instantiates the "register for different roles" objective)_
- [ ] 4.3.3 Test Account Provisioning _(fit? review-only)_
- [ ] 4.3.4 Account Enumeration _(fit? differential oracle, awkward flag)_
- [ ] 4.3.5 Weak/Unenforced Username Policy _(fit? review-only)_

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

## 4.6 Session Management — 1/9
- [x] 4.6.1 Session Management Schema _(forgeable base64 token → forge admin session → canary)_
- [ ] 4.6.2 Cookie Attributes _(fit? config-weakness)_
- [ ] 4.6.3 Session Fixation _(fit? needs victim)_
- [ ] 4.6.4 Exposed Session Variables _(fit? real SESS-04 = transport/cache exposure: HTTPS downgrade, Cache-Control, session-id-in-GET; config-weakness)_
- [ ] 4.6.5 CSRF _(fit? needs victim; impact is a forced action, not flag-recovery)_
- [ ] 4.6.6 Logout Functionality _(fit? session-still-valid, weak flag)_
- [ ] 4.6.7 Session Timeout _(fit? config-weakness)_
- [ ] 4.6.8 Session Puzzling _(buildable but intricate)_
- [ ] 4.6.9 Session Hijacking _(fit? needs a leak/victim)_

## 4.7 Input Validation — 10/19
- [x] 4.7.1 Reflected XSS
- [x] 4.7.2 Stored XSS
- _→ 4.7.3 HTTP Verb Tampering (merged into 4.2.6 ✅)_
- [x] 4.7.4 HTTP Parameter Pollution
- [~] 4.7.5 SQL Injection — POLYGLOT extraction class (sqlite/pg/mysql via shared layer + infraVariant; T0 UNION, T1 forces blind boolean). [x] .4 PostgreSQL (validated T0+T1) · [~] .2 MySQL (built; Fly revalidation pending API credits) · _.1 Oracle / .3 SQL Server / .5 MS Access — hosting impractical_ · [ ] .6 NoSQL _(distinct, Mongo)_ · [ ] .7 ORM · [ ] .8 Client-side
- [ ] 4.7.6 LDAP Injection _(sidecar)_
- [x] 4.7.7 XML Injection _(XXE file-read — real libxml2 external entity → reads server-side canary file)_
- [ ] 4.7.8 SSI Injection _(sidecar)_
- [x] 4.7.9 XPath Injection _(BLIND boolean extraction — char-by-char via substring(), binary auth oracle, real XPath engine)_
- [ ] 4.7.10 IMAP/SMTP Injection _(sidecar)_
- [x] 4.7.11 Code Injection — [ ] .1 LFI · [ ] .2 RFI
- [x] 4.7.12 Command Injection
- [ ] 4.7.13 Format String _(OOS — C/C++)_
- [ ] 4.7.14 Incubated Vulnerability
- [ ] 4.7.15 HTTP Splitting/Smuggling _(needs raw-socket/proxy)_
- [ ] 4.7.16 HTTP Incoming Requests
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

## 4.10 Business Logic — 0/9
- [ ] 4.10.1 Data Validation · [ ] 4.10.2 Forge Requests · [ ] 4.10.3 Integrity Checks · [ ] 4.10.4 Process Timing · [ ] 4.10.5 Function Usage Limits · [ ] 4.10.6 Circumvent Workflows · [ ] 4.10.7 Defenses vs Misuse · [ ] 4.10.8 Upload Unexpected Types · [ ] 4.10.9 Upload Malicious Files
  _(mostly buildable but each needs a bespoke workflow + canary chain)_

## 4.11 Client-side — 2/13
- [x] 4.11.1 DOM-Based XSS
- [x] 4.11.2 JavaScript Execution
- [ ] 4.11.3 HTML Injection _(browser oracle + DOM-element check)_
- [ ] 4.11.4 Client-side URL Redirect _(browser oracle + final-URL check)_
- [ ] 4.11.5 CSS Injection _(CSS-exfil — awkward)_
- [ ] 4.11.6 Client-side Resource Manipulation
- [ ] 4.11.7 CORS _(buildable — permissive CORS → cross-origin read)_
- [ ] 4.11.8 Cross-Site Flashing _(OOS — Flash EOL)_
- [ ] 4.11.9 Clickjacking _(fit? config-weakness)_
- [ ] 4.11.10 WebSockets _(sidecar)_
- [ ] 4.11.11 Web Messaging _(browser oracle + postMessage action)_
- [ ] 4.11.12 Browser Storage _(browser oracle + localStorage read)_
- [ ] 4.11.13 Cross-Site Script Inclusion

## 4.12 API — 0/1
- [ ] 4.12.1 GraphQL _(sidecar)_
