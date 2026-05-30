// Per-deploy injection-location anchor for reflected XSS (4.7.1).
// Reflected XSS happens wherever HTML reflects user input — search results
// (query), search-form errors (body-form), "back to" links from Referer
// (header), SPA-style URL segments reflected into titles (path-segment).
//
// body-json reflection is rare in classic reflected XSS — skip.
export const INJECTION_LOCATIONS = ['query', 'body-form', 'header', 'path-segment']
