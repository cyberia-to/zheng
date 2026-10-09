# BBG integration

the [[BBG]] (the authenticated state structure for [[cyber]]) and [[zheng]] share one hash, [[hemera]], and one field, [[Goldilocks]]. a zheng statement about state names a state root; zheng itself authenticates every read against that root before the read becomes part of the relation.

## how a proof reads state

| step | mechanism |
|---|---|
| statement | `StateStatement`: the state root (four field limbs), and one public lookup per lookup site of the compiled relation (active flag, namespace, key, value) |
| evidence | `StateEvidence`: the leaves fold to the root by hemera `compress4`; every carried table matches its leaf (a hash commitment of the padded fields, length in the header) |
| check | the verifier authenticates the evidence first, then pins the active flag, root limbs, namespace, key and value of every read in the relation |
| profiles | state-public v3 (envelope profile 3, witness disclosed), succinct state statements (profile 1), private state for the zk profile and the MPC-in-the-head fallback |

a read can be forged only by a hemera collision in the root fold or in a table commitment — the hash row of [[zheng/specs/soundness|the soundness ledger]]. limits: 4096 reads, 2^20 fields per table.

## what changes with the repair

the old picture — one expander-code (Brakedown) commitment serving both the proof's opening and BBG's indexes, with evaluation proofs but without Merkle paths — is retired: that commitment had no real opening ([[zheng/docs/explanation/recursive-brakedown|recursive-brakedown]]). today the state tables are carried whole and checked against their hash commitment, which is sound and linear in the table size. the [[soft3/proposals/proof-system-repair|proof-system repair]] migrates BBG's `QueryProof` onto the Reed–Solomon commitment that won the phase-2 bake-off (WHIR), so that a state query and a proof open the same kind of commitment, with Merkle paths, at a size polylogarithmic in the table rather than linear.

[[LogUp]] lookup arguments use the [[sumcheck]] protocol — the same sumcheck that powers [[SuperSpartan]]; cross-index consistency (every edge appearing in the neuron, source and target indexes) reduces to a sumcheck over logarithmic multiplicities.

see [[recursion]] for accumulation and composition, [[performance]] for measured figures, [[trace-to-proof]] for the proving pipeline
