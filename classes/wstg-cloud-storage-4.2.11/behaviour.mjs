// WSTG-CONF-11 (wstg-cloud-storage-4.2.11) — exposed bucket/listing.
// Lead-driven: the bucket root path is referenced in reachable content
// (asset URLs / docs), validated reachable from /. The sensitive object then
// found by reading the open listing.
import { makeHiddenEndpointClassDef } from '../_shared/hidden-endpoint-base.mjs'

export const classDef = makeHiddenEndpointClassDef({
  wstgId: 'WSTG-CONF-11',
  className: 'Cloud Storage Exposure',
  discoveryMode: 'lead',
  discoveryTarget: 'canary-prefix',
})
