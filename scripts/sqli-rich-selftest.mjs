// In-process self-test for the rich polyglot SQLi class (sqlite). Confirms the
// DB is richly populated and both exploit paths recover the buried canary.
import crypto from 'node:crypto'
import { classDef, __test } from '../classes/wstg-sqli-4.7.5.4/behaviour.mjs'

const scenario = {
  dialect: 'sqlite',
  itemsTable: 'catalogue_items',
  itemsPools: {
    title: ['Trail Runner X', 'Summit Pack 40L', 'Alpine Shell', 'River Sandal', 'Cedar Tent', 'Basalt Stove', 'Otter Drybag', 'Heron Bottle'],
    body: ['lightweight and durable', 'waterproof ripstop', 'breathable membrane', 'packs to fist size', 'three-season rated', 'titanium build'],
  },
  sensitiveTable: 'staff_accounts',
  accountPool: ['j.doe', 'a.smith', 'support', 'ops', 'billing', 'm.lee', 'warehouse', 'k.ng'],
  secretPool: ['sk_live_4f1a9c', 'tok_88a2bb', 'key_77ffaa', 'pat_19ce', 'sk_live_aa11', 'tok_55dd'],
  canaryAccount: 'admin',
  decoyTables: [
    { name: 'orders', columns: ['customer', 'status'], pools: { customer: ['Acme', 'Globex', 'Initech', 'Umbrella'], status: ['paid', 'shipped', 'refunded', 'pending'] } },
    { name: 'sessions', columns: ['token', 'ua'], pools: { token: ['s_1', 's_2', 's_3', 's_4'], ua: ['Chrome', 'Safari', 'Firefox', 'Edge'] } },
  ],
  endpoint: { path: '/search', method: 'GET' },
  slots: { user_input: { name: 'q', location: 'query' } },
  body: '{RESULTS}',
}
const canary = 'pr_' + crypto.randomBytes(12).toString('hex')

// confirm population sizes
const db = await __test.getDb(scenario, canary)
const items = await db.query('SELECT COUNT(*) AS n FROM catalogue_items')
const creds = await db.query('SELECT COUNT(*) AS n FROM staff_accounts')
const orders = await db.query('SELECT COUNT(*) AS n FROM orders')
console.log(`rows: items=${items[0].n} staff_accounts=${creds[0].n} orders=${orders[0].n}`)

function makeHelpers(blockUnion) {
  return {
    fireScenarioRequest: async ({ payload }) => {
      if (blockUnion && /u\W*n\W*i\W*o\W*n/i.test(payload)) return { body: 'BLOCKED (403)' }
      const d = await __test.getDb(scenario, canary)
      let rows
      try { rows = await d.query(`SELECT id, title, body FROM ${scenario.itemsTable} WHERE body LIKE '%${payload}%'`) } catch { rows = [] }
      return { body: rows.map(r => `<article class="result-card"><b>${r.title}</b><span>${r.body}</span></article>`).join('') }
    },
  }
}

const r0 = await classDef.fireExploit({ scenario, perDeployCanary: canary, helpers: makeHelpers(false) })
console.log('T0 (UNION dump):', r0.body.includes(canary) ? 'OK ✅' : 'FAIL ❌')
const r1 = await classDef.fireExploit({ scenario, perDeployCanary: canary, helpers: makeHelpers(true) })
console.log('T1 (blind)    :', r1.body.includes(canary) ? 'OK ✅ -> ' + r1.body : 'FAIL ❌ -> ' + r1.body)
