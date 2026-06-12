// Validate a trace (or traces) against the PolyRange Attack Trace schema.
// Uses ajv (JSON Schema 2020-12). Exit 0 if all valid, 1 otherwise.
//
//   node validate-trace.mjs <schema.json> <trace.json> [<trace2.json> ...]

import fs from 'node:fs/promises'
import Ajv2020 from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'

const [schemaPath, ...tracePaths] = process.argv.slice(2)
if (!schemaPath || tracePaths.length === 0) {
  console.error('usage: node validate-trace.mjs <schema.json> <trace.json> [...]')
  process.exit(2)
}

const ajv = new Ajv2020({ allErrors: true, strict: false })
addFormats(ajv)
const schema = JSON.parse(await fs.readFile(schemaPath, 'utf-8'))
const validate = ajv.compile(schema)

let allOk = true
for (const p of tracePaths) {
  const data = JSON.parse(await fs.readFile(p, 'utf-8'))
  const ok = validate(data)
  if (ok) {
    console.log(`VALID   ${p}  (${data.steps?.length ?? 0} steps, solved=${data.outcome?.solved}, served=${data.agent?.model_served})`)
  } else {
    allOk = false
    console.log(`INVALID ${p}`)
    for (const e of validate.errors ?? []) console.log(`  - ${e.instancePath || '/'} ${e.message}`)
  }
}
process.exit(allOk ? 0 : 1)
