// WSTG-CONF-04 (wstg-backup-files-4.2.4) — forced-browsing of exposed files/endpoints; shared base.
import { makeHiddenEndpointClassDef } from '../_shared/hidden-endpoint-base.mjs'

export const classDef = makeHiddenEndpointClassDef({
  wstgId: 'WSTG-CONF-04',
  className: 'Backup and Unreferenced Files',
})
