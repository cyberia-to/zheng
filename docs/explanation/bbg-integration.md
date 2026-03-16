# BBG integration

the [[BBG]] (the authenticated state structure for [[cyber]]) uses [[WHIR]]-based polynomial commitments for all indexes. the same WHIR instance that serves as the stark PCS also handles state operations — one polynomial commitment scheme for proofs and state.

## shared primitives

| operation | mechanism | constraints |
|---|---|---|
| EdgeSet membership | WHIR evaluation proof | ~1,000 |
| namespace completeness | sorted range bounds + WHIR opens | ~10,000 |
| cross-index consistency | [[LogUp]] via [[sumcheck]] | ~5,000 |
| focus commitment | polynomial over (neuron, π) | ~1,000 |
| balance commitment | polynomial over (neuron, balance) | ~1,000 |

[[LogUp]] lookup arguments use the [[sumcheck]] protocol — the same sumcheck that powers [[SuperSpartan]]. cross-index consistency (every edge appearing in neuron index, source index, and target index) reduces to a sumcheck over logarithmic multiplicities. one protocol, two uses.

## why this matters

the unification of PCS across proofs and state eliminates a translation layer. a [[zheng]] proof that verifies a state transition uses the same WHIR commitment that the BBG uses to authenticate the state itself. the verifier does not need separate cryptographic machinery for "check the proof" and "check the state" — both reduce to WHIR evaluation proofs over [[Goldilocks]] field elements hashed by [[hemera]].

this is also why batch verification works: multiple WHIR openings (some from proofs, some from state queries) can be batched into a single verification pass. the amortized cost per opening drops as the batch grows.

see [[recursion]] for how proofs compose, [[performance]] for constraint costs, [[trace-to-proof]] for the proving pipeline
