// In-process self-test for the polyglot SQLi extraction class (sqlite engine).
// Exercises the REAL classDef.fireExploit through both paths:
//   - UNION allowed   -> T0 direct extraction
//   - UNION blocked    -> T1 blind boolean extraction
import crypto from 'node:crypto'
import { classDef, __test } from '../classes/wstg-sqli-4.7.5.4/behaviour.mjs'

const scenario = {
  dialect: 'sqlite',
  itemsTable: 'catalog_items',
  vaultTable: 'internal_secrets',
  vaultLabel: 'master_api_key',
  items: Array.from({ length: 10 }, (_, i) => ({ title: `Catalogue item ${i + 1}`, body: `public listing number ${i + 1} with some descriptive text` })),
  vaultDecoys: [{ name: 'smtp_password', value: 'decoy-smtp-xyz' }, { name: 'cache_key', value: 'decoy-cache-abc' }],
  endpoint: { path: '/search', method: 'GET' },
  slots: { user_input: { name: 'q', location: 'query' } },
  body: '{RESULTS}',
}
const canary = 'pr_' + crypto.randomBytes(12).toString('hex')

function makeHelpers(blockUnion) {
  return {
    fireScenarioRequest: async ({ payload }) => {
      if (blockUnion && /u\W*n\W*i\W*o\W*n/i.test(payload)) return { body: 'BLOCKED — request denied (403)' }
      const db = await __test.getDb(scenario, canary)
      let rows
      try { rows = await db.query(`SELECT id, title, body FROM ${scenario.itemsTable} WHERE body LIKE '%${payload}%'`) }
      catch { rows = [] }
      const cards = rows.map(r => `<article class="result-card"><b>${r.title}</b><span>${r.body}</span></article>`).join('')
      return { body: cards }
    },
  }
}

const r0 = await classDef.fireExploit({ scenario, perDeployCanary: canary, helpers: makeHelpers(false) })
console.log('target canary :', canary)
console.log('T0 (UNION)    :', r0.body.includes(canary) ? 'OK ✅' : 'FAIL ❌')

const r1 = await classDef.fireExploit({ scenario, perDeployCanary: canary, helpers: makeHelpers(true) })
console.log('T1 (blind)    :', r1.body.includes(canary) ? 'OK ✅  -> ' + r1.body : 'FAIL ❌ -> ' + r1.body)
