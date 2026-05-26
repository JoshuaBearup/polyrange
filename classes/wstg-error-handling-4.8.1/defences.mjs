// Improper error handling — T0 only. The vuln is information disclosure via a
// verbose error path, not a defence to bypass: malformed input trips the leak.
// (A future T1 could add partial error handling — generic 500 on common errors,
// a less-obvious input still hitting the verbose path — but that's a refinement.)

export const defences = {
  0: {
    // Malformed JSON → the parser throws → verbose debug page leaks the canary.
    canonicalPayload: () => '{ "unterminated": ',
    naiveBlockedExpected: false,
    bypassPayloads: [],
  },
}
