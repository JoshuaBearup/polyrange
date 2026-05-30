// Per-deploy injection-location anchor for SSRF (4.7.19).
// SSRF input — a URL the server fetches — can ride in any HTTP position.
// Query (URL preview), JSON body (webhook config), form (avatar fetcher),
// header (X-Forwarded-Host into proxy follow-up; X-Custom-Webhook). Header
// SSRF is famously common (X-Forwarded-For → cloud metadata).
//
// path-segment URL-as-segment is uncommon in real apps — skip.
export const INJECTION_LOCATIONS = ['query', 'body-form', 'body-json', 'header']
