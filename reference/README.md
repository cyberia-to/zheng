---
tags: computer science, cryptography
---
# zheng reference

precise definitions, parameters, APIs, and constraint costs for each component zheng implements. these pages answer "what exactly is X" — the spec you consult when implementing or auditing.

for intuition, motivation, and learning paths see [docs/explanation](../docs/explanation/). for the FRI→STIR→WHIR evolution (historical context, not implemented) see [[fri-to-whir]].

## what zheng implements

- [[whir]] — Weights Help Improving Rate. multilinear PCS with sub-millisecond verification
- [[sumcheck]] — interactive proof reducing exponential sums to one evaluation
- [[superspartan]] — IOP for Customizable Constraint Systems ([[CCS]]) via sumcheck
- [[polynomial-commitment]] — commit-then-open primitive, WHIR instantiation over Goldilocks

## proof pipeline

- [[transcript]] — Fiat-Shamir transcript construction, domain separation, sponge protocol
- [[constraints]] — AIR constraint format, pattern table, CCS encoding, constraint budgets
- [[verifier]] — standalone verifier algorithm, cost breakdown, nox pattern decomposition
- [[recursion-spec]] — recursive composition protocol, tree/fold/DAG topologies, depth bounds
- [[api]] — prover/verifier/fold interface, data types, usage patterns
