// Per-deploy SQL dialect anchor. Each dialect runs against a real engine:
// sqlite in-process (sql.js), postgres + mysql as real servers in-container
// (selected via classDef.infraVariant -> Dockerfile.<dialect>).
// POLYRANGE_SQL_DIALECT pins it (per-dialect validation); else a uniform pick.
const DIALECTS = ['sqlite', 'postgres', 'mysql']

export function pickAnchor() {
  const pin = process.env.POLYRANGE_SQL_DIALECT
  const dialect = (pin && DIALECTS.includes(pin)) ? pin : DIALECTS[Math.floor(Math.random() * DIALECTS.length)]
  return {
    dialect,
    note: `Build a ${dialect}-backed admin login. Set scenario.dialect to "${dialect}". The login query runs against a real ${dialect} database.`,
  }
}
