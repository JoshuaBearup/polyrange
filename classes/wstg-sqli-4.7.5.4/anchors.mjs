// Per-deploy SQL dialect anchor (same pool as the auth-bypass class). Each
// dialect runs against a real engine via classDef.infraVariant -> Dockerfile.<dialect>.
const DIALECTS = ['sqlite', 'postgres', 'mysql']
export function pickAnchor() {
  const pin = process.env.POLYRANGE_SQL_DIALECT
  const dialect = (pin && DIALECTS.includes(pin)) ? pin : DIALECTS[Math.floor(Math.random() * DIALECTS.length)]
  return {
    dialect,
    note: `Build a ${dialect}-backed catalogue search. Set scenario.dialect to "${dialect}". The search query runs against a real ${dialect} database.`,
  }
}
