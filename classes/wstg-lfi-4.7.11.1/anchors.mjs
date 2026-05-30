// Per-deploy injection-location anchor for LFI (4.7.11.1).
// Real-world LFI input rides through query (?topic=home), form-body
// (POST search forms that include by name), headers (X-Locale → pick
// localised template; X-Tenant → pick tenant-specific page), and cookies
// (sticky last-viewed section). path-segment is uncommon for php include()
// flows and body-json is rare (mobile APIs rarely include() server-side).
export const INJECTION_LOCATIONS = ['query', 'body-form', 'header', 'cookie']
