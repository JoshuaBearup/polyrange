// LDAP injection auth bypass. The reference payload injects )(|(uid=* into the
// username so the filter becomes (&(uid=*)(|(uid=*)(userPassword=...))) — an
// always-true OR that matches every entry regardless of password. T0 only.
export const defences = {
  0: {
    canonicalPayload: () => '*)(|(uid=*',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
