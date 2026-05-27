// NoSQL (Mongo) operator injection. The reference payload sends operator objects
// instead of string credentials so the query matches without a password. T0.
export const defences = {
  0: { canonicalPayload: () => '{"username":{"$ne":null},"password":{"$ne":null}}', naiveBlockedExpected: false, bypassPayloads: [] },
}
