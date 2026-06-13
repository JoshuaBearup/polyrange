// Knowledge-graph vocabulary for PolyRange attack traces.
//
// The step stream is already a graph, not just a list: each request touches an
// endpoint, tests a parameter, and each successful inference discovers a table,
// a column, or the flag. This module is the STABLE vocabulary that turns a
// stream of schema steps into typed nodes and edges — deterministically, and
// grounded in fields the schema already carries (action.detail + tags), so it
// adds no schema surface and never invents structure the trace didn't record.
//
// It is a pure fold: foldStep(graph, step) mutates an accumulating graph, and
// stepsToGraph(steps) folds a whole trace. The same fold drives both the
// post-hoc view (fold a finished trace) and the live TUI (fold each step as it
// arrives), so the two can never diverge.
//
// Node types:  endpoint | param | table | column | hypothesis | flag
// Edge rels:   probed | tests | injectable | discovers | leaks | submits | confirmed-by
//
// Grounding rule: extract tables/columns from the SQL in the agent's OWN
// payload (FROM <t>, SELECT <cols>, sqlite_master, information_schema), not by
// guessing at response text. The payload is structured and authored by the
// agent; the response is noisy. We only assert a discovery the agent provably
// asked for.

export const NODE_TYPES = ['endpoint', 'param', 'table', 'column', 'hypothesis', 'flag']
export const EDGE_RELS = ['probed', 'tests', 'injectable', 'discovers', 'leaks', 'submits', 'confirmed-by']

export function emptyGraph() {
  return { nodes: new Map(), edges: new Map() }
}

function addNode(g, type, id, label, meta = {}) {
  const key = `${type}:${id}`
  const existing = g.nodes.get(key)
  if (existing) {
    existing.hits++
    Object.assign(existing.meta, meta)
    return existing
  }
  const node = { key, type, id, label: label ?? id, hits: 1, firstStep: meta.firstStep ?? null, meta }
  g.nodes.set(key, node)
  return node
}

function addEdge(g, fromKey, rel, toKey, step) {
  const key = `${fromKey}|${rel}|${toKey}`
  const existing = g.edges.get(key)
  if (existing) { existing.count++; existing.lastStep = step; return existing }
  const edge = { key, from: fromKey, rel, to: toKey, count: 1, firstStep: step, lastStep: step }
  g.edges.set(key, edge)
  return edge
}

// --- extractors (pure, defensive) ---------------------------------------

function urlPath(url) {
  if (!url) return null
  try { const u = new URL(url); return u.pathname || '/' } catch { return null }
}

function urlParams(url) {
  if (!url) return []
  try { return [...new URL(url).searchParams.keys()] } catch { return [] }
}

// query/body params from the raw shell command (covers --data / --data-urlencode
// bodies the URL object can't see).
function bodyParams(command) {
  if (!command) return []
  const out = []
  const re = /--data(?:-urlencode)?\s+(['"]?)([^'"&\s]+?)=/g
  let m
  while ((m = re.exec(command))) out.push(decodeURIComponent(m[2]))
  return out
}

// Tables/columns the agent's OWN SQL names. Grounded, not guessed.
function sqlEntities(text) {
  const tables = new Set()
  const columns = new Set()
  if (!text) return { tables: [], columns: [] }
  const t = String(text)
  if (/sqlite_master/i.test(t)) tables.add('sqlite_master')
  if (/information_schema\.(tables|columns)/i.test(t)) tables.add('information_schema')
  for (const m of t.matchAll(/\bFROM\s+([a-zA-Z_][\w$]*)/gi)) tables.add(m[1].toLowerCase())
  for (const m of t.matchAll(/\bJOIN\s+([a-zA-Z_][\w$]*)/gi)) tables.add(m[1].toLowerCase())
  // column list of an explicit SELECT a,b,c FROM — only simple identifier lists,
  // skip * and function calls to avoid over-claiming.
  for (const m of t.matchAll(/\bSELECT\s+([\w\s,]+?)\s+FROM\b/gi)) {
    for (const raw of m[1].split(',')) {
      const c = raw.trim()
      if (/^[a-zA-Z_][\w$]*$/.test(c) && c.toLowerCase() !== 'null') columns.add(c.toLowerCase())
    }
  }
  return { tables: [...tables], columns: [...columns] }
}

const SQL_TABLE_NOISE = new Set(['information_schema', 'sqlite_master'])

// --- the fold -----------------------------------------------------------

// Fold one step into the graph. Returns the set of node keys touched this step
// (so a live renderer can flash "new this turn"). Pure w.r.t. the step; mutates g.
export function foldStep(g, step) {
  const touched = []
  const i = step.index
  const a = step.action || {}
  const detail = a.detail || {}
  const tags = step.tags || []
  const command = detail.command || ''
  const obsText = step.observation ? (step.observation.detail ?? step.observation.summary ?? '') : ''
  const obsStr = typeof obsText === 'string' ? obsText : JSON.stringify(obsText ?? '')
  const isError = tags.includes('error-signal') || step.observation?.status === 'error'

  if (a.kind === 'http_request') {
    const path = detail.url ? urlPath(detail.url) : null
    const epId = path || (detail.method ? `${detail.method} ?` : '?')
    const ep = addNode(g, 'endpoint', epId, path || epId, { method: detail.method, firstStep: i })
    touched.push(ep.key)
    addEdge(g, 'agent:attacker', 'probed', ep.key, i)

    const params = [...new Set([...urlParams(detail.url), ...bodyParams(command)])]
    for (const p of params) {
      const pn = addNode(g, 'param', `${epId}#${p}`, p, { endpoint: epId, firstStep: i })
      touched.push(pn.key)
      addEdge(g, ep.key, 'tests', pn.key, i)

      if (tags.includes('payload')) {
        // a hypothesis = the injection technique aimed at this param
        const tech = /UNION/i.test(command) ? 'union-sqli'
          : /sqlite_master|information_schema/i.test(command) ? 'schema-enum'
          : /OR\s+'?1'?='?1|AND\s+1=1/i.test(command) ? 'boolean-sqli'
          : 'sqli'
        const hy = addNode(g, 'hypothesis', `${pn.id}:${tech}`, `${tech} on ${p}`, { param: pn.key, firstStep: i })
        touched.push(hy.key)
        addEdge(g, hy.key, 'tests', pn.key, i)
        // injectable only when the payload came back WITHOUT an error signal —
        // i.e. the parameter accepted the injection.
        if (!isError) addEdge(g, pn.key, 'injectable', hy.key, i)
      }
    }

    // schema discovery: tables/columns named in the agent's payload, attributed
    // to the endpoint that carried it. Only when a payload was actually sent.
    if (tags.includes('payload')) {
      const { tables, columns } = sqlEntities(command)
      for (const tbl of tables) {
        const tn = addNode(g, 'table', tbl, tbl, { firstStep: i })
        touched.push(tn.key)
        addEdge(g, ep.key, 'discovers', tn.key, i)
      }
      for (const col of columns) {
        const cn = addNode(g, 'column', col, col, { firstStep: i })
        touched.push(cn.key)
        // attribute the column to a concrete table when exactly one non-noise
        // table is in play this step; otherwise leave it endpoint-attributed.
        const realTables = tables.filter(x => !SQL_TABLE_NOISE.has(x))
        const owner = realTables.length === 1 ? `table:${realTables[0]}` : ep.key
        addEdge(g, owner, 'leaks', cn.key, i)
      }
    }
  }

  // flag handling — independent of action kind
  if (tags.includes('submit') || tags.includes('flag-confirmed')) {
    const flagVal = (obsStr.match(/pr_[0-9a-f]{24}/) || command.match(/pr_[0-9a-f]{24}/) || [])[0] || 'flag'
    const fn = addNode(g, 'flag', flagVal, flagVal, { firstStep: i })
    touched.push(fn.key)
    if (tags.includes('submit')) addEdge(g, 'agent:attacker', 'submits', fn.key, i)
    if (tags.includes('flag-confirmed')) {
      fn.meta.confirmed = true
      addEdge(g, fn.key, 'confirmed-by', `step:${i}`, i)
    }
  }

  return touched
}

export function stepsToGraph(steps) {
  const g = emptyGraph()
  for (const s of steps || []) foldStep(g, s)
  return g
}

// Serialise to plain arrays (for JSON output / assertions / a UI payload).
export function graphToJSON(g) {
  return {
    nodes: [...g.nodes.values()].map(({ key, type, id, label, hits, meta }) => ({ key, type, id, label, hits, ...(meta.confirmed ? { confirmed: true } : {}) })),
    edges: [...g.edges.values()].map(({ from, rel, to, count }) => ({ from, rel, to, count })),
  }
}

export function graphStats(g) {
  const byType = {}
  for (const n of g.nodes.values()) byType[n.type] = (byType[n.type] || 0) + 1
  const byRel = {}
  for (const e of g.edges.values()) byRel[e.rel] = (byRel[e.rel] || 0) + 1
  return { nodes: g.nodes.size, edges: g.edges.size, byType, byRel }
}
