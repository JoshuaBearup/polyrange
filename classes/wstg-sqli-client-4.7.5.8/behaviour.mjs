// WSTG-INPV-05.8 — Client-Side SQL Injection.
// The server hands the browser a static page that boots sql.js (SQLite in
// WebAssembly), seeds a public catalogue plus a sensitive credentials
// table (canary buried in the privileged row), and runs a user-supplied
// search against that in-browser engine. The query is built by string
// concatenation in the page JS, so a UNION-style payload reads the
// sensitive table and the rendered result row carries the canary in the
// DOM. The browser oracle observes that DOM and proves recovery.
//
// Tier ladder:
//   T0 — raw concatenation; ' UNION SELECT id, account, secret FROM <s> --
//        lands directly in the results panel.
//   T1 — a client-side denylist strips UNION / -- / ; before the query is
//        constructed. Bypasses: comment-styles the filter misses (block
//        comments, mixed case), or error/CAST side-channel.

import { Scenario } from './scenario.mjs'

// Public CDN delivery for sql.js (v1; documented in constraints.md). Pinned
// to an exact version so deploys are deterministic and offline-replayable
// against a recorded artefact set if needed later.
const SQLJS_VERSION = '1.10.3'
const SQLJS_BASE = `https://cdnjs.cloudflare.com/ajax/libs/sql.js/${SQLJS_VERSION}`

const esc = s => String(s).replace(/'/g, "''")

// Synthesize a small public catalogue deterministically from the scenario
// pools. Kept tiny (~12 rows) because every row ships to the browser; the
// schema realism is in the table layout and the second sensitive table.
function buildCatalogueRows(scenario) {
  const { title, body } = scenario.itemsPools
  const rows = []
  const n = Math.min(12, Math.min(title.length, body.length))
  for (let i = 0; i < n; i++) rows.push({ id: i + 1, title: title[i], body: body[i] })
  return rows
}

function buildSensitiveRows(scenario, canary) {
  const { accountPool, secretPool, canaryAccount } = scenario
  const rows = []
  const n = Math.min(12, Math.min(accountPool.length, secretPool.length))
  for (let i = 0; i < n; i++) rows.push({ id: i + 1, account: accountPool[i], secret: secretPool[i] })
  // Bury the canary in a deterministic but non-first slot so naive
  // observers don't see it without actually selecting from the table.
  const slot = Math.min(rows.length - 1, Math.max(1, Math.floor(rows.length / 2)))
  rows[slot] = { id: slot + 1, account: canaryAccount, secret: canary }
  return rows
}

function seedSql(scenario, canary) {
  const items = buildCatalogueRows(scenario)
  const sens = buildSensitiveRows(scenario, canary)
  const lines = []
  lines.push(`DROP TABLE IF EXISTS ${scenario.itemsTable};`)
  lines.push(`CREATE TABLE ${scenario.itemsTable} (id INTEGER, title TEXT, body TEXT);`)
  for (const r of items) {
    lines.push(`INSERT INTO ${scenario.itemsTable} (id, title, body) VALUES (${r.id}, '${esc(r.title)}', '${esc(r.body)}');`)
  }
  lines.push(`DROP TABLE IF EXISTS ${scenario.sensitiveTable};`)
  lines.push(`CREATE TABLE ${scenario.sensitiveTable} (id INTEGER, account TEXT, secret TEXT);`)
  for (const r of sens) {
    lines.push(`INSERT INTO ${scenario.sensitiveTable} (id, account, secret) VALUES (${r.id}, '${esc(r.account)}', '${esc(r.secret)}');`)
  }
  return lines.join('\n')
}

// The client-side boot script. Loads sql.js from a CDN, seeds both tables,
// reads the user-supplied lookup value out of the URL query, builds the
// SELECT by raw concatenation (T0) or after a denylist filter (T1), runs
// it, and renders the rows into #pr-sqlic-out. The sensitive secret column
// is rendered as text content — if a UNION-style payload pivots the SELECT
// onto the sensitive table, the canary surfaces in the DOM.
function bootScript({ scenario, canary, tier }) {
  const slotName = scenario.slots.user_input.name
  const seed = seedSql(scenario, canary)
  // T1 denylist runs BEFORE query construction. Strips the canonical
  // tokens a flat-footed attacker reaches for. Bypass paths: mixed-case
  // UNION inside block comments (UnI/**/oN), or substr/like side-channel.
  const filterJs = tier >= 1
    ? `function filterInput(raw){ return String(raw).replace(/union/gi,'').replace(/--/g,'').replace(/;/g,''); }`
    : `function filterInput(raw){ return String(raw); }`
  return `
    <script src="${SQLJS_BASE}/sql-wasm.js"></script>
    <script>
      (function(){
        ${filterJs}
        var SEED = ${JSON.stringify(seed)};
        var TABLE = ${JSON.stringify(scenario.itemsTable)};
        var SLOT = ${JSON.stringify(slotName)};
        function render(rows){
          var host = document.getElementById('pr-sqlic-out');
          if (!host) return;
          if (!rows || !rows.length){ host.innerHTML = '<p style="color:#666;padding:24px 0">No matching results.</p>'; return; }
          var html = '<div style="display:grid;gap:12px;padding:16px 0">';
          for (var i=0;i<rows.length;i++){
            var r = rows[i] || [];
            html += '<article class="result-card" style="border:1px solid #e5e5e5;border-radius:8px;padding:16px;background:#fafafa">';
            for (var j=0;j<r.length;j++){
              var v = (r[j] == null) ? '' : String(r[j]);
              html += '<div style="font-size:14px;margin-top:4px">' + v.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</div>';
            }
            html += '</article>';
          }
          html += '</div>';
          host.innerHTML = html;
        }
        function run(SQL){
          var db = new SQL.Database();
          db.exec(SEED);
          var params = new URLSearchParams(location.search);
          var raw = params.get(SLOT) || '';
          if (!raw.trim()){
            var host = document.getElementById('pr-sqlic-out');
            if (host) host.innerHTML = '<p style="color:#666;padding:24px 0">Enter a search term to begin.</p>';
            return;
          }
          var input = filterInput(raw);
          // VULNERABLE: user input concatenated into the WHERE clause.
          var sql = "SELECT id, title, body FROM " + TABLE + " WHERE body LIKE '%" + input + "%'";
          try {
            var res = db.exec(sql);
            var rows = (res && res[0] && res[0].values) ? res[0].values : [];
            render(rows);
          } catch (e) {
            var host = document.getElementById('pr-sqlic-out');
            if (host) host.innerHTML = '<pre class="db-error" style="color:#b00">' + String(e.message || e).replace(/</g,'&lt;') + '</pre>';
          }
        }
        function boot(){
          if (typeof initSqlJs !== 'function') { setTimeout(boot, 50); return; }
          initSqlJs({ locateFile: function(f){ return ${JSON.stringify(SQLJS_BASE)} + '/' + f; } }).then(run);
        }
        boot();
      })();
    </script>`
}

export const classDef = {
  wstgId: 'WSTG-INPV-05.8',
  class: 'Client-Side SQL Injection',
  defenceTiers: [0, 1],
  Scenario,
  needsSignup: false,
  // Canary is templated into the page at render time (seeded into the
  // in-browser DB), not baked into the scenario JSON the LLM saw.
  canaryRuntime: true,
  // The sink and the engine live in the browser. The HTTP body alone does
  // not prove recovery — the canary appears only after sql.js loads, seeds,
  // and the injected query runs. The browser oracle is the success signal.
  clientSideExecution: true,
  discoveryMode: 'observation',
  discoveryTargetPath: (s) => s.endpoint.path,
  discoveryStaticOk: (s) =>
    typeof s.chromeInjection?.html === 'string' && s.chromeInjection.html.includes(s.endpoint.path),

  matchesRequest({ reqUrl, req, scenario }) {
    if (req.method !== (scenario.endpoint.method || 'GET')) return false
    return reqUrl.pathname === scenario.endpoint.path
  },

  async handleRequest({ scenario, renderPage, manifest }) {
    const tier = manifest.defenceTier || 0
    const canary = manifest.perDeployCanary || ''
    const boot = bootScript({ scenario, canary, tier })
    const body = scenario.body
      .replace('{RESULTS}', '<div id="pr-sqlic-out" data-pr-canary></div>')
      .replace('{BOOT}', boot)
    return { status: 200, body: renderPage(body) }
  },

  // HTTP fetch only confirms the shell page was served. Real proof is the
  // browser oracle navigating to exploitObservationUrl, booting sql.js,
  // running the concatenated query, and surfacing the canary in the DOM.
  async fireExploit({ baseUrl, scenario, payload, helpers }) {
    return helpers.fireScenarioRequest({ scenario, payload })
  },

  exploitObservationUrl({ baseUrl, scenario, payload }) {
    const slot = scenario.slots.user_input
    const u = new URL(`${baseUrl}${scenario.endpoint.path}`)
    if (slot.location === 'query') {
      u.searchParams.set(slot.name, payload)
      return u.toString()
    }
    // path-segment fallback (rare for this class)
    if (slot.location === 'path-segment') {
      return `${baseUrl}${scenario.endpoint.path.replace(new RegExp(`[:{]${slot.name}\\}?`), encodeURIComponent(payload))}`
    }
    return null
  },

  // Fallback success check used by non-browser callers; the browser oracle
  // is the authoritative signal for this class because the canary only
  // appears post-WASM-boot.
  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

export const __test = { seedSql, bootScript, buildCatalogueRows, buildSensitiveRows }
