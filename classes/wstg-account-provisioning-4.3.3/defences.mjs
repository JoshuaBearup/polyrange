// Provisioning — canonical exploit signs up as the customer tier, POSTs
// /invite with role=admin to create a new admin account, logs in as that
// admin, reads adminDataPath, recovers canary. T0 only.
export const defences = {
  0: {
    canonicalPayload: () => 'invite-self-as-admin',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
