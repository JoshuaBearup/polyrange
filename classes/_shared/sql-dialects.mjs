// Shared multi-dialect SQL layer for polyglot SQL-injection classes.
// One async interface over three real engines:
//   - sqlite  : in-process via sql.js (pure WASM — no native build, no server)
//   - postgres: real server in-container, via `pg` (DATABASE_URL)
//   - mysql   : real server in-container, via `mysql2` (MYSQL_URL / localhost)
// query() lets SQL errors throw, so injection mistakes surface real, dialect-
// specific error text (fingerprinting), exactly as a live target would.

export async function makeDb(dialect) {
  if (dialect === 'sqlite') {
    const initSqlJs = (await import('sql.js')).default
    const SQL = await initSqlJs()
    const db = new SQL.Database()
    return {
      dialect,
      async run(sql) { db.run(sql) },
      async query(sql) {
        const res = db.exec(sql)               // throws on SQL error
        if (!res.length) return []
        const { columns, values } = res[0]
        return values.map(row => Object.fromEntries(columns.map((c, i) => [c, row[i]])))
      },
    }
  }

  if (dialect === 'postgres') {
    const pg = (await import('pg')).default
    const client = new pg.Client({ connectionString: process.env.DATABASE_URL })
    await client.connect()
    return {
      dialect,
      async run(sql) { await client.query(sql) },
      async query(sql) { return (await client.query(sql)).rows },
    }
  }

  if (dialect === 'mysql') {
    const mysql = await import('mysql2/promise')
    const conn = await mysql.createConnection(
      process.env.MYSQL_URL || { host: '127.0.0.1', user: 'root', password: 'polyrange', database: 'app', multipleStatements: false }
    )
    return {
      dialect,
      async run(sql) { await conn.query(sql) },
      async query(sql) { const [rows] = await conn.query(sql); return rows },
    }
  }

  throw new Error(`unknown SQL dialect: ${dialect}`)
}

// Conventional admin-targeting comment bypass that works across all three
// dialects (the trailing space makes "-- " a valid comment in MySQL too).
export function authBypassPayload(adminUsername) {
  return `${adminUsername}'-- `
}
