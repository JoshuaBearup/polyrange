// PolyRange code-injection backend — Node. A REAL eval() sink on a localhost
// HTTP server, separate from the front runtime. The per-deploy canary is in
// process.env; the attacker injects JS that dumps it. (ESM: the app's root
// package.json sets type:module.)
import http from 'node:http'

const PORT = parseInt(process.env.PR_BACKEND_PORT || '9001', 10)
const PARAM = process.env.PR_PARAM || 'expr'

http.createServer((req, res) => {
  let body = ''
  req.on('data', (c) => { body += c })
  req.on('end', () => {
    const code = new URLSearchParams(body).get(PARAM) || ''
    let result
    try {
      result = eval(code)            // VULNERABLE: user input evaluated as JS
    } catch (e) {
      result = 'error: ' + e.message
    }
    const out = String(result)
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' })
    res.end(out)
  })
}).listen(PORT, '127.0.0.1')
