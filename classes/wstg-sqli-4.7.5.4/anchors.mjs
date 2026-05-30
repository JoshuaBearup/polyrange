// Per-deploy SQL dialect anchor (same pool as the auth-bypass class). Each
// dialect runs against a real engine via classDef.infraVariant -> Dockerfile.<dialect>.
const DIALECTS = ['sqlite', 'postgres', 'mysql']

// Per-deploy injection-location anchor. Real-world SQLi input rides through
// query (theme-named lookup parameter), form-body (admin lookup form),
// JSON-body (mobile/SPA API), headers (X-Tenant-Id / X-Locale / X-Request-ID
// looked up server-side), cookies (sticky preference / tenant cookie fed
// into a query), and path-segments (REST routes like /products/:slug where
// the slug is concatenated into a WHERE clause — /products/x' OR '1'='1).
export const INJECTION_LOCATIONS = ['query', 'body-form', 'body-json', 'header', 'cookie', 'path-segment']

export function pickAnchor() {
  const pin = process.env.POLYRANGE_SQL_DIALECT
  const dialect = (pin && DIALECTS.includes(pin)) ? pin : DIALECTS[Math.floor(Math.random() * DIALECTS.length)]
  return {
    dialect,
    note: `Build a ${dialect}-backed catalogue search. Set scenario.dialect to "${dialect}". The search query runs against a real ${dialect} database.`,
  }
}
