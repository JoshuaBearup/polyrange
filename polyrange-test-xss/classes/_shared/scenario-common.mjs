// Shared schema fragments every class scenario needs.
// Field names defined here exist nowhere else.

import { z } from 'zod'

export const Endpoint = z.object({
  path: z.string().min(1).describe('URL path the scenario lives at'),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).default('GET'),
})

export const ChromeInjection = z.object({
  location: z.enum(['header-search', 'header-end', 'footer', 'nav-extra'])
    .describe('Where in the chrome the discovery affordance is inserted'),
  html: z.string().min(1).describe('HTML fragment that points at the scenario endpoint'),
  description: z.string().describe('One-line description of what the injection adds'),
})

export const Slot = z.object({
  name: z.string().describe('Realistic parameter name (e.g. q, query, id, search)'),
  location: z.enum(['query', 'body-form', 'body-json', 'header', 'path-segment'])
    .describe('Where the parameter appears in the HTTP request'),
})

// Render a Zod object schema as LLM-readable instructions.
// Defensively handles wrappers (refine, transform, optional, default, branded).
export function describeSchema(schema, indent = 0) {
  const pad = '  '.repeat(indent)
  const tn = schema?._def?.typeName

  // Unwrap wrappers — keep peeling until we hit a base type
  if (tn === 'ZodEffects' || tn === 'ZodBranded' || tn === 'ZodLazy' || tn === 'ZodPipeline') {
    const inner = schema._def.schema || schema._def.type || schema._def.in || schema
    return describeSchema(inner, indent)
  }
  if (tn === 'ZodOptional' || tn === 'ZodNullable' || tn === 'ZodDefault') {
    return describeSchema(schema._def.innerType, indent)
  }
  if (tn === 'ZodObject') {
    const lines = ['{']
    for (const [k, v] of Object.entries(schema._def.shape())) {
      const opt = (v.isOptional?.() || v._def?.typeName === 'ZodOptional') ? ' (optional)' : ''
      const desc = unwrapDescription(v)
      lines.push(`${pad}  "${k}"${opt}: ${describeSchema(v, indent + 1)}${desc ? `  // ${desc}` : ''},`)
    }
    lines.push(`${pad}}`)
    return lines.join('\n')
  }
  if (tn === 'ZodArray') return `[${describeSchema(schema._def.type, indent)}, ...]`
  if (tn === 'ZodEnum') return schema._def.values.map(v => `"${v}"`).join(' | ')
  if (tn === 'ZodNativeEnum') return Object.values(schema._def.values).map(v => `"${v}"`).join(' | ')
  if (tn === 'ZodUnion' || tn === 'ZodDiscriminatedUnion') {
    return schema._def.options.map(o => describeSchema(o, indent)).join(' | ')
  }
  if (tn === 'ZodRecord') return `Record<string, ${describeSchema(schema._def.valueType, indent)}>`
  if (tn === 'ZodLiteral') return JSON.stringify(schema._def.value)
  if (!tn) return 'any'
  return tn.replace('Zod', '').toLowerCase()
}

// Description can live on the schema itself OR be hidden inside a ZodEffects wrapper.
function unwrapDescription(schema) {
  if (!schema) return ''
  if (schema.description) return schema.description
  const inner = schema._def?.schema || schema._def?.innerType || schema._def?.type
  return inner ? unwrapDescription(inner) : ''
}
