// Class-aware scenario generator — schema is the source of truth.
// Imports the class's Scenario Zod schema. Derives the LLM prompt from it.
// Validates LLM output against the same schema. Single field-name source.

import fs from 'node:fs/promises'
import path from 'node:path'
import { callLLM } from './call-llm.mjs'
import { describeSchema } from '../classes/_shared/scenario-common.mjs'

const SYSTEM = `You generate scenario surfaces for vulnerability-class benchmarks.

Output strict JSON matching the schema given. No commentary. No markdown.

ALWAYS:
- Realistic application names and field values
- Names and identifiers from the natural distribution of real apps
- Per-deploy unique content

NEVER:
- "polyrange", "benchmark", "test", "demo" anywhere
- Synthetic-looking identifiers (random hex suffixes on parameter names)
- Lorem ipsum or stub content`

export async function generateScenarioForClass(theme, classDir, perDeployCanary) {
  const classId = path.basename(classDir)
  const { Scenario } = await import(path.resolve(classDir, 'scenario.mjs'))
  let requirements = ''
  try {
    requirements = await fs.readFile(path.join(classDir, 'requirements.md'), 'utf-8')
  } catch {}

  const schemaDescription = describeSchema(Scenario)

  const user = `Generate a scenario for vulnerability class: ${classId}

THEME:
${JSON.stringify(theme, null, 2)}

PER-DEPLOY CANARY (embed in the location the schema's descriptions call out):
  ${perDeployCanary}

OUTPUT SCHEMA — your response must validate against this:

${schemaDescription}

CLASS-SPECIFIC REQUIREMENTS (prose only — field names come from the schema above):

${requirements}

Generate the scenario. Return ONLY valid JSON matching the schema. No commentary, no markdown fences.`

  // Up to 3 attempts: validate against the schema. Reprompt with the error on failure.
  let lastError = ''
  for (let attempt = 0; attempt < 3; attempt++) {
    const userWithFeedback = attempt === 0 ? user :
      `${user}\n\nYour previous attempt failed validation:\n${lastError}\n\nTry again — output must validate.`

    const raw = await callLLM({
      system: SYSTEM,
      user: userWithFeedback,
      expectJson: true,
      maxTokens: 8192,
      quality: true,  // Opus for the scenario
    })

    const result = Scenario.safeParse(raw)
    if (result.success) {
      return result.data
    }
    lastError = result.error.issues.map(i => `  - ${i.path.join('.')}: ${i.message}`).join('\n')
    console.log(`  ⚠ scenario validation failed (attempt ${attempt + 1}):\n${lastError}`)
  }
  throw new Error(`Scenario validation failed after 3 attempts. Last error:\n${lastError}`)
}
