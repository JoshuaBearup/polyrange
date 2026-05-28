// ORM Injection — canonical exploit submits an operator-shaped JSON filter
// (e.g. `{"id":{"$gt":0}}`) that the permissive operator-alias map honours
// as Sequelize Op symbols, enumerating the table and surfacing the canary
// row's body. T0 only.
export const defences = {
  0: {
    canonicalPayload: () => 'orm-operator-injection',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
