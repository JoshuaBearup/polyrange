// WSTG-APIT-01 (4.12.1) — GraphQL behaviour.
// A real graphql-js endpoint with introspection enabled. The schema carries a
// privileged query/field (holding the canary) that the public docs never
// mention — so it is discoverable only by introspecting the schema, then
// queryable to read the canary.

import { buildSchema, graphql } from 'graphql'
import { Scenario } from './scenario.mjs'

let SCHEMA = null
let ROOT = null
function gql(scenario, canary) {
  if (!SCHEMA) {
    const sdl = `
      type ${scenario.publicTypeName} { id: ID name: String }
      type ${scenario.privilegedTypeName} { ${scenario.secretFieldName}: String }
      type Query {
        ${scenario.publicQueryName}: [${scenario.publicTypeName}]
        ${scenario.privilegedQueryName}: ${scenario.privilegedTypeName}
      }
    `
    SCHEMA = buildSchema(sdl)
    ROOT = {
      [scenario.publicQueryName]: () => (scenario.publicItems || []).map((n, i) => ({ id: String(i + 1), name: n })),
      [scenario.privilegedQueryName]: () => ({ [scenario.secretFieldName]: canary }),
    }
  }
  return { schema: SCHEMA, rootValue: ROOT }
}

export const classDef = {
  wstgId: 'WSTG-APIT-01',
  class: 'GraphQL',
  defenceTiers: [0],
  Scenario,
  needsSignup: false,
  canaryRuntime: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path),

  matchesRequest({ reqUrl, scenario }) {
    return reqUrl.pathname === scenario.endpoint.path
  },

  async handleRequest({ req, scenario, helpers, renderPage, manifest }) {
    if (req.method !== 'POST') return { status: 200, body: renderPage(docsPage(scenario)) }
    let query = '', variables = null
    try {
      const body = JSON.parse(helpers.rawBody || '{}')
      query = body.query || ''
      variables = body.variables || null
    } catch { /* leave empty */ }
    const { schema, rootValue } = gql(scenario, manifest.perDeployCanary)
    const result = await graphql({ schema, source: query, rootValue, variableValues: variables })
    return { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8' }, body: JSON.stringify(result) }
  },

  // Reference exploit: query the privileged field (discoverable via introspection).
  async fireExploit({ baseUrl, scenario }) {
    const query = `{ ${scenario.privilegedQueryName} { ${scenario.secretFieldName} } }`
    const r = await fetch(`${baseUrl}${scenario.endpoint.path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query }), redirect: 'manual',
    })
    return { status: r.status, body: await r.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

export const __test = { gql }

function docsPage(scenario) {
  const example = `{ "query": "{ ${scenario.publicQueryName} { id name } }" }`
  return `<section style="max-width:640px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 8px">${escapeHtml(scenario.featureLabel)} — GraphQL API</h2>
  <p style="color:#666;margin:0 0 12px">POST GraphQL queries to <code>${scenario.endpoint.path}</code> as JSON.</p>
  <p style="font-size:13px;color:#666">Example — list ${escapeHtml(scenario.publicQueryName)}:</p>
  <pre style="background:#f3f3f3;padding:12px;border-radius:6px">${escapeHtml(example)}</pre>
</section>`
}
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
