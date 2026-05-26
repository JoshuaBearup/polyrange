// Shared victim-record synthesizer.
// Classes provide value pools per field + the canary record's fields; this
// expands them into a realistic population of records with a per-deploy
// identifier scheme, placing the canary at a random position. Used by any
// class with a backing data population the attacker enumerates or extracts
// (IDOR, SQLi sensitive/primary tables, future BOLA/BFLA/stored-XSS).

import crypto from 'node:crypto'

// pools:        { fieldName: [values...] }       — sampled per record
// canaryFields: { fieldName: value } | null      — the one canary record (null = no canary in this set)
// scheme:       'sequential-integer'|'uuid'|'base62'|'slug'
// count:        number of records to synthesize
// ownerPrefix:  string prefix for synthetic owner_session values
// Returns: [{ identifier, ownerSessionId, fields, isCanaryRecord }]
export function synthesizeRecords({ pools, canaryFields = null, scheme, count, ownerPrefix = 'sess' }) {
  const fieldNames = Object.keys(pools)
  const ids = generateIdSet(scheme, count)
  const canarySlot = canaryFields ? Math.floor(Math.random() * count) : -1

  return ids.map((id, i) => {
    const isCanary = i === canarySlot
    const fields = isCanary
      ? { ...canaryFields }
      : Object.fromEntries(fieldNames.map(f => [f, pick(pools[f])]))
    return {
      identifier: id,
      ownerSessionId: `${ownerPrefix}_${crypto.randomBytes(6).toString('hex')}`,
      fields,
      isCanaryRecord: isCanary,
    }
  })
}

// Generate `count` unique identifiers in the chosen scheme.
// Sequential is contiguous from a random base (real auto-increment) so the
// population enumerates as a clean range; a signed-up user's own record lands
// just above it. Non-sequential schemes are intentionally non-enumerable.
function generateIdSet(scheme, count) {
  const ids = new Set()
  if (scheme === 'sequential-integer') {
    const base = 1000 + Math.floor(Math.random() * 900000)
    for (let i = 0; i < count; i++) ids.add(String(base + i))
    return [...ids]
  }
  let guard = 0
  while (ids.size < count && guard++ < count * 20) ids.add(genOne(scheme))
  return [...ids]
}

function genOne(scheme) {
  if (scheme === 'uuid') return crypto.randomUUID()
  if (scheme === 'base62') return base62(crypto.randomBytes(8))
  if (scheme === 'slug') {
    const adj = ['quiet', 'bright', 'soft', 'tall', 'kind', 'sharp', 'warm', 'true', 'low', 'far', 'deep', 'fair']
    const noun = ['river', 'hill', 'field', 'shore', 'lane', 'pine', 'stone', 'maple', 'ridge', 'cove', 'bluff', 'fern']
    return `${pick(adj)}-${pick(noun)}-${Math.floor(Math.random() * 9999)}`
  }
  throw new Error(`unknown identifierScheme: ${scheme}`)
}

function base62(buf) {
  const a = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
  let n = BigInt('0x' + buf.toString('hex'))
  let s = ''
  while (n > 0n) { s = a[Number(n % 62n)] + s; n /= 62n }
  return s || '0'
}

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)] }

// Random population size for a deploy — varied so a fixed count isn't a tell.
// Up to ~1000 so enumeration is a genuine sweep, not "try the one other id".
export function randomPopulationSize(min = 150, max = 1000) {
  return min + Math.floor(Math.random() * (max - min + 1))
}

// Batched multi-row INSERT so seeding ~1000 rows doesn't stall container boot.
// Table shape is (id, owner_session, data JSONB). Pass the class's quoteIdent.
export async function bulkInsertRecords(db, tableNameQuoted, records, batchSize = 200) {
  for (let i = 0; i < records.length; i += batchSize) {
    const batch = records.slice(i, i + batchSize)
    const values = []
    const params = []
    batch.forEach((r, j) => {
      const o = j * 3
      values.push(`($${o + 1}, $${o + 2}, $${o + 3})`)
      params.push(String(r.identifier), r.ownerSessionId, JSON.stringify(r.fields))
    })
    await db.query(
      `INSERT INTO ${tableNameQuoted} (id, owner_session, data) VALUES ${values.join(', ')}`,
      params
    )
  }
}
