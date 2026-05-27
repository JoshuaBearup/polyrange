// Seed the webmail user's maildir from the baked manifest: benign INBOX
// messages + one admin-mailbox message holding the per-deploy canary.
import fs from 'node:fs'
const m = JSON.parse(fs.readFileSync('/app/manifest.json', 'utf8'))
const adm = (m.scenario && m.scenario.adminMailbox) || 'Administration'
const canary = m.perDeployCanary || 'pr_unknown'
const subjects = (m.scenario && m.scenario.inboxSubjects) || ['Welcome aboard']
const base = '/srv/mail/webmail/Maildir'
for (const folder of [base, `${base}/.${adm}`]) {
  for (const sub of ['cur', 'new', 'tmp']) fs.mkdirSync(`${folder}/${sub}`, { recursive: true })
}
function writeMsg(folder, n, subj, body) {
  const content = `From: system@localhost\r\nTo: webmail@localhost\r\nSubject: ${subj}\r\nDate: Mon, 01 Jan 2026 00:00:00 +0000\r\n\r\n${body}\r\n`
  fs.writeFileSync(`${folder}/cur/${1700000000 + n}.pr${n}.polyrange:2,S`, content)
}
subjects.forEach((s, i) => writeMsg(base, i + 1, s, `Message: ${s}`))
writeMsg(`${base}/.${adm}`, 1, 'Internal administration', `license_key=${canary}`)
console.log(`[seed] maildir seeded (admin mailbox: ${adm})`)
