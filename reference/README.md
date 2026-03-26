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
five [[lens|lenses]]: one trait, five algebras — each algebra sees through its own optic.
five operations: **commit**, **open**, **verify**, **fold**, **decide**.

## spec pages

- [[lens]] — polynomial commitment (separate repo: ~/git/lens/)
- [[sumcheck]] — the engine: O(N) prover reduces exponential sum to one evaluation
- [[superspartan]] — CCS IOP via sumcheck: any-degree constraints, one Lens opening
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
├── lens layer (external: ~/git/lens/)
│   ├── Brakedown lens        (nebu, F_p)       expander-graph codes, Merkle-free
│   ├── Binius lens           (kuro, F₂)        binary Reed-Solomon
│   ├── Ring-aware lens       (jali, R_q)       NTT batch, automorphisms, noise tracking
│   ├── Isogeny lens          (genies, F_q)     Brakedown over isogeny field
│   └── Tropical lens         (trop, min+)      witness-verify, delegates to Brakedown
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

## five lenses

specs live in [[lens]] repo (~/git/lens/).

| lens | algebra | repo | commitment | verification | primary workloads |
|------|---------|------|-----------|-------------|-------------------|
| Brakedown | F_p | [[nebu]] | expander-graph linear code | ~660 F_p ops, ~5 μs | proofs, hashing, state |
| Binius | F₂ | [[kuro]] | binary Reed-Solomon | ~660 F₂ ops | quantized inference, SpMV |
| Ring-aware | R_q | [[jali]] | NTT-batched Brakedown | ring-structured | FHE bootstrapping, lattice KEM |
| Isogeny | F_q | [[genies]] | Brakedown over F_q | ~660 F_q ops | stealth, VDF, blind signatures |
| Tropical | min,+ | [[trop]] | witness-verify via Brakedown | F_p dual certificate | shortest path, assignment, Viterbi |

## five operations

| operation | what it does | cost |
|-----------|-------------|------|
| **commit** | encode trace as multilinear polynomial via Lens backend | O(N) field ops |
| **open** | prove evaluation at sumcheck output point | O(N) field ops, proof ~1.3 KiB |
| **verify** | check sumcheck transcript + Lens opening | O(λ log log N) field ops, ~5 μs |
| **fold** | absorb one CCS instance into running accumulator | ~30 field ops + 1 hemera hash |
| **decide** | produce final proof from accumulated folds | ~825 constraints (CCS jet + batch + algebraic FS) |

## cross-algebra composition

any nox program can mix algebras. each sub-trace proves via its native Lens. HyperNova folds all into one F_p accumulator. one decider, one proof, regardless of how many algebras participated.

boundary cost: ~766 F_p constraints per algebra crossing. at 5 algebras max: ~3,830 overhead for a fully heterogeneous computation. negligible vs execution cost.

for intuition, motivation, and learning paths see [docs/explanation](../docs/explanation/).
