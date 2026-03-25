---
tags: computer science, cryptography
diffusion: 0.00010722364868599256
springs: 0.00007795330796863797
heat: 0.00009023976773977348
focus: 0.00009504577028154114
gravity: 0
density: 0.73
---
# zheng: polynomial proof system

one PCS: recursive [[Brakedown]] (Goldilocks, expander-graph codes, Merkle-free, O(N) commit).
one IOP: [[SuperSpartan]] + [[sumcheck]] (CCS constraints, O(N) prover, O(log N) verifier).
one folding: [[HyperNova]] (CCS-native, ~30 field ops per fold, one decider at the end).
one hash: [[hemera]] (~3 calls per proof — binding, Fiat-Shamir seed, domain separation).
one field: [[Goldilocks field]] (p = 2^64 - 2^32 + 1, 4-5 cycle multiply via [[nebu]]).

five operations: **commit**, **open**, **verify**, **fold**, **decide**.

## spec pages

- [[polynomial-commitment]] — recursive Brakedown PCS: O(N) commit, O(log N + lambda) proof, O(lambda log log N) verify
- [[sumcheck]] — the engine: O(N) prover reduces exponential sum to one evaluation
- [[superspartan]] — CCS IOP via sumcheck: any-degree AIR constraints, one PCS opening
- [[recursion]] — HyperNova folding + proof-carrying computation
- [[accumulator]] — universal accumulator: fold all 5 structural sync layers ([[bbg]])
- [[binius]] — F2 tower PCS for binary workloads (2 of 14 nox languages)
- [[tensor]] — tensor compression for O(sqrt(N)) memory in Brakedown opening
- [[verifier]] — ~89-825 constraint decider (CCS jet + batch + algebraic FS)
- [[constraints]] — CCS format, pattern table, state operations
- [[transcript]] — Fiat-Shamir via hemera (~3 calls)
- [[api]] — commit/open/verify/fold/decide entry points

## architecture

```
zheng
├── IOP layer (field-generic)
│   ├── SuperSpartan          CCS constraint system
│   ├── sumcheck              exponential sum reduction
│   └── HyperNova             folding + composition
│
├── PCS layer
│   ├── Brakedown (Goldilocks) expander-graph codes, Merkle-free
│   └── Binius (F₂ tower)     binary Reed-Solomon with packing
│
├── hash layer
│   └── hemera                ~3 calls total
│                             Fiat-Shamir + binding hash
│
└── composition
    └── HyperNova folding     ~30 field ops + 1 hemera hash per fold
        └── decider           one SuperSpartan + sumcheck + Brakedown proof
```

## five operations

| operation | what it does | cost |
|-----------|-------------|------|
| **commit** | encode trace as multilinear polynomial via Brakedown | O(N) field ops |
| **open** | prove evaluation at sumcheck output point | O(N) field ops, proof ~1.3 KiB |
| **verify** | check sumcheck transcript + Brakedown opening | O(lambda log log N) field ops, ~5 us |
| **fold** | absorb one CCS instance into running accumulator | ~30 field ops + 1 hemera hash |
| **decide** | produce final proof from accumulated folds | ~825 constraints (CCS jet + batch + algebraic FS) |

for intuition, motivation, and learning paths see [docs/explanation](../docs/explanation/).
