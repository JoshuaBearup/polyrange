// Tier router — returns a request inspector for the deploy's defence tier.
// Each inspector returns either { blocked: true, status, body } or { blocked: false }.

import { createT1WAF } from './t1-waf.mjs'

export function createInspector(defenceTier, defenceConfig) {
  if (!defenceTier || defenceTier === 0) {
    return async () => ({ blocked: false })
  }
  if (defenceTier === 1) {
    return createT1WAF(defenceConfig?.waf || {})
  }
  // T2/T3/T4 not yet implemented
  throw new Error(`Defence tier ${defenceTier} not implemented`)
}
