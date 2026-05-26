// Stored XSS — reuses the reflected-XSS WAF rule pool + bypasses. The WAF
// inspects the POST submission body (the stored-XSS sink), so a naive
// <script> submission is blocked and an event-handler bypass survives to be
// stored and rendered unescaped on the view page.

export { RULE_POOL, BYPASS_TEMPLATES, defences, generateT1Config } from '../wstg-xss-4.7.1/defences.mjs'
