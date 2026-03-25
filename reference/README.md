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

one IOP: [[SuperSpartan]] + [[sumcheck]] (CCS constraints, O(N) prover, O(log N) verifier).
one folding: [[HyperNova]] (CCS-native, ~30 field ops per fold, one decider at the end).
one hash: [[hemera]] (~3 calls per proof — binding, Fiat-Shamir seed, domain separation).
five PCS backends: one trait, five algebras.
five operations: **commit**, **open**, **verify**, **fold**, **decide**.

## spec pages

- [[pcs]] — generic PCS interface: commit, open, verify (the trait)
- [[expander-pcs]] — PCS₁: Goldilocks backend via expander-graph codes, Merkle-free ([[nebu]])
- [[binary-pcs]] — PCS₂: F₂ tower backend via binary Reed-Solomon ([[kuro]])
- [[ring-pcs]] — PCS₃: R_q ring-aware backend, NTT batching, automorphism exploitation ([[jali]])
- [[isogeny-pcs]] — PCS₄: F_q backend via Brakedown over isogeny field ([[genies]])
- [[tropical-pcs]] — PCS₅: (min,+) witness-verify via structured delegation to PCS₁ ([[trop]])
- [[sumcheck]] — the engine: O(N) prover reduces exponential sum to one evaluation
- [[superspartan]] — CCS IOP via sumcheck: any-degree constraints, one PCS opening
- [[recursion]] — HyperNova folding + proof-carrying computation + cross-algebra
- [[accumulator]] — universal accumulator: fold all 5 structural sync layers
- [[tensor]] — tensor compression for O(√N) prover memory
- [[verifier]] — ~89-825 constraint decider (CCS jet + batch + algebraic FS)
- [[constraints]] — CCS format, pattern table, state operations
- [[transcript]] — Fiat-Shamir via hemera (~3 calls)
- [[api]] — commit/open/verify/fold/decide entry points

## architecture

```
zheng
├── IOP layer (field-generic, shared across all algebras)
│   ├── SuperSpartan          CCS constraint system
│   ├── sumcheck              exponential sum reduction
│   └── HyperNova             folding + composition
│
├── PCS layer (one trait, five backends)
│   ├── PCS₁: Brakedown       (nebu, F_p)       expander-graph codes, Merkle-free
│   ├── PCS₂: Binius          (kuro, F₂)        binary Reed-Solomon
│   ├── PCS₃: Ring-aware      (jali, R_q)       NTT batch, automorphisms, noise tracking
│   ├── PCS₄: Isogeny         (genies, F_q)     Brakedown over isogeny field
│   └── PCS₅: Tropical        (trop, min+)      witness-verify, delegates to PCS₁
│
├── hash layer
│   └── hemera                ~3 calls total
│                             Fiat-Shamir + binding hash
│
├── selector CCS (cross-algebra dispatch)
│   ├── sel_Fp                Goldilocks rows
│   ├── sel_F2                binary rows
│   ├── sel_ring              ring-structured rows
│   ├── sel_Fq                isogeny rows
│   └── sel_trop              tropical witness-verify rows
│
└── composition
    └── HyperNova folding     ~30 field ops + 1 hemera hash per fold
        └── decider           one SuperSpartan + sumcheck + Brakedown proof
                              covers ALL algebras, runs once in F_p
```

## five PCS backends

| PCS | algebra | repo | commitment | verification | primary workloads |
|-----|---------|------|-----------|-------------|-------------------|
| PCS₁ | F_p | [[nebu]] | expander-graph linear code | ~660 F_p ops, ~5 μs | proofs, hashing, state |
| PCS₂ | F₂ | [[kuro]] | binary Reed-Solomon | ~660 F₂ ops | quantized inference, SpMV |
| PCS₃ | R_q | [[jali]] | ring-aware Brakedown + NTT batch | ring-structured | FHE bootstrapping, lattice KEM |
| PCS₄ | F_q | [[genies]] | Brakedown over F_q | ~660 F_q ops | stealth, VDF, blind signatures |
| PCS₅ | min,+ | [[trop]] | delegates to PCS₁ | F_p dual certificate | shortest path, assignment, Viterbi |

## five operations

| operation | what it does | cost |
|-----------|-------------|------|
| **commit** | encode trace as multilinear polynomial via PCS backend | O(N) field ops |
| **open** | prove evaluation at sumcheck output point | O(N) field ops, proof ~1.3 KiB |
| **verify** | check sumcheck transcript + PCS opening | O(λ log log N) field ops, ~5 μs |
| **fold** | absorb one CCS instance into running accumulator | ~30 field ops + 1 hemera hash |
| **decide** | produce final proof from accumulated folds | ~825 constraints (CCS jet + batch + algebraic FS) |

## cross-algebra composition

any nox program can mix algebras. each sub-trace proves via its native PCS. HyperNova folds all into one F_p accumulator. one decider, one proof, regardless of how many algebras participated.

boundary cost: ~766 F_p constraints per algebra crossing. at 5 algebras max: ~3,830 overhead for a fully heterogeneous computation. negligible vs execution cost.

for intuition, motivation, and learning paths see [docs/explanation](../docs/explanation/).
