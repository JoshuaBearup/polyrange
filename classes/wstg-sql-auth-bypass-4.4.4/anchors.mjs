// Per-deploy SQL dialect anchor. SQLite first (in-process, no server); postgres
// and mysql are added once the multi-engine image lands. POLYRANGE_SQL_DIALECT
// pins it (for per-dialect validation); otherwise a uniform random pick.
const DIALECTS = ['sqlite'] // ['sqlite','postgres','mysql'] after the multi-engine image

export function pickAnchor() {
  const pin = process.env.POLYRANGE_SQL_DIALECT
  const dialect = (pin && DIALECTS.includes(pin)) ? pin : DIALECTS[Math.floor(Math.random() * DIALECTS.length)]
  return {
    dialect,
    note: `Build a ${dialect}-backed admin login. Set scenario.dialect to "${dialect}". The login query runs against a real ${dialect} database.`,
  }
}
