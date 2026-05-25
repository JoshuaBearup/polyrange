// WSTG-INPV-01 — Reflected XSS behaviour.
// Imports the Scenario schema; field names not re-declared anywhere.

import { Scenario } from './scenario.mjs'

export const classDef = {
  wstgId: 'WSTG-INPV-01',
  class: 'Reflected XSS',
  defenceTiers: [0, 1, 2, 3, 4],
  Scenario,

  // Render the page with user input reflected unescaped.
  // `rawScenario` is the JSON from manifest; `parse()` enforces the schema.
  template: ({ rawScenario, userInput }) => {
    const scenario = Scenario.parse(rawScenario)
    return {
      status: 200,
      body: scenario.body.replaceAll('{INPUT}', userInput),
    }
  },

  exploitSuccessCriterion: ({ responseBody, perDeployCanary }) => {
    // Behavioural detection emits the canary into the response when XSS fires.
    // For the simple regex test path (without a real headless browser yet),
    // we accept the canary in the response body as proof.
    return responseBody.includes(perDeployCanary)
  },
}
