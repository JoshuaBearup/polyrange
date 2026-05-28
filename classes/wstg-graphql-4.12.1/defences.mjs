// GraphQL — the exploit introspects then queries the privileged field. The
// canonical query is built in fireExploit from the privileged names. T0.
export const defences = {
  0: { canonicalPayload: () => 'graphql-introspect-privileged', naiveBlockedExpected: false, bypassPayloads: [] },
}
