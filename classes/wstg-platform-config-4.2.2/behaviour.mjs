// WSTG-CONF-02 (wstg-platform-config-4.2.2) — forced-browsing of exposed files/endpoints; shared base.
import { makeHiddenEndpointClassDef } from '../_shared/hidden-endpoint-base.mjs'

export const classDef = makeHiddenEndpointClassDef({
  wstgId: 'WSTG-CONF-02',
  className: 'Application Platform Configuration',
})
