// Per-deploy injection-location anchor for SSTI (4.7.18).
// Server-side template engines render user input from any HTTP position. The
// classic shape is a POST form field for "personalised message" or "comment",
// but headers (X-Locale → message template), JSON body (mobile-API message
// previews), and query (templated email subject preview) are all real.
//
// path-segment is rare for free-form template input — omit.
export const INJECTION_LOCATIONS = ['query', 'body-form', 'body-json', 'header']
