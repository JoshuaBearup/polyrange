// WSTG-ATHZ-04 — IDOR behaviour.

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-ATHZ-04',
  class: 'IDOR',
  defenceTiers: [0, 1, 2, 3, 4],
  Scenario,

  template: ({ rawScenario, requestedId, session }) => {
    const scenario = Scenario.parse(rawScenario)
    const record = scenario.principalRecords.find(r => String(r.identifier) === String(requestedId))
    if (!record) {
      return { status: 404, body: renderNotFound(scenario.body) }
    }
    // ← THE VULN: no check that record.ownerSessionId === session
    const renderedDetails = renderRecordHTML(record.fields)
    return {
      status: 200,
      body: scenario.body.replace('{RECORD_DETAILS}', renderedDetails),
    }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) => {
    return responseBody.includes(perDeployCanary)
  },
}

function renderRecordHTML(fields) {
  return '<dl class="record-fields">' +
    Object.entries(fields).map(([k, v]) =>
      `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(String(v))}</dd>`
    ).join('') +
    '</dl>'
}

function renderNotFound(bodyTemplate) {
  return bodyTemplate.replace('{RECORD_DETAILS}', '<p class="not-found">Resource not found.</p>')
}

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
