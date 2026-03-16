---
tags: computer science, cryptography
---
# zheng reference

precise definitions, parameters, APIs, and constraint costs for each component of the proof system. these pages answer "what exactly is X" — the spec you consult when implementing or auditing.

for intuition, motivation, and learning paths see [docs/explanation](../docs/explanation/).

## protocols

- [[fri]] — Fast Reed-Solomon IOP. baseline low-degree test (2018)
- [[stir]] — Shift To Improve Rate. fewer queries via rate improvement (2024)
- [[whir]] — Weights Help Improving Rate. richest queries, sub-millisecond verification (2025)

## building blocks

- [[sumcheck]] — interactive proof reducing exponential sums to one evaluation
- [[superspartan]] — IOP for Customizable Constraint Systems (CCS) via sumcheck
- [[polynomial-commitment]] — commit-then-open primitive, WHIR instantiation over Goldilocks

## planned

- transcript — Fiat-Shamir transcript construction and domain separation
- constraints — AIR constraint format and encoding rules
- verifier — standalone verifier algorithm and circuit decomposition
- recursion-spec — recursive composition protocol and depth bounds
- api — prover/verifier interface and data formats
