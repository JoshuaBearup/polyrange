// WSTG-INFO-06 (wstg-entry-points-4.1.6) — discovery/forced-browsing recon.
// Observation-driven: the canary entry point is referenced in normally-served
// content (a form action / inline fetch), validated reachable from /.
import { makeHiddenEndpointClassDef } from '../_shared/hidden-endpoint-base.mjs'

export const classDef = makeHiddenEndpointClassDef({
  wstgId: 'WSTG-INFO-06',
  className: 'Entry Point Identification',
  discoveryMode: 'observation',
  discoveryTarget: 'canary-path',
})
