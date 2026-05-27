// SQL-injection auth bypass — the login query is string-concatenated. The
// reference exploit injects an always-true OR + comment into the username,
// returning the admin row (the trailing space keeps "-- " a valid comment in
// MySQL too, so it is universal across sqlite/postgres/mysql).
export const defences = {
  0: {
    canonicalPayload: () => `' OR '1'='1' -- `,
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
