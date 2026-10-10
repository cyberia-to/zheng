---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: Customizable Constraint Systems
---
# CCS

Customizable Constraint Systems. a unified constraint framework that generalizes [[R1CS]], Plonkish ([[PLONK]]/Halo2), and [[AIR]] into one representation. Setty, Thaler, Wahby (2023).

```
CCS instance: (M₁, ..., M_t, S₁, ..., S_q, c₁, ..., c_q)

constraint:  Σⱼ cⱼ · ∏_{i ∈ Sⱼ} Mᵢ · z = 0

special cases:
  R1CS:     t=3, q=2, c₁=1, c₂=-1        → degree 2
  Plonkish: selector polynomials → M        → custom gates
  AIR:      shifted rows → M                → transition constraints
```

the unification matters because a proof system handling CCS handles all three — including AIR constraints of any degree. [[SuperSpartan]] is this proof system.

## why CCS matters for zheng

in [[zheng]], the relation compiler turns a [[nox]] program and the shape of its subject into one CCS whose rows range in degree from 1 (add, sub) to 7 (hemera's Poseidon2 S-box rows). the verifier compiles the same CCS itself and pins the public prefix `(1 ‖ io ‖ cycles)` — the constant wire, inputs, outputs and cost. classical R1CS can only express degree-2 constraints, requiring high-degree operations to be decomposed into many degree-2 gates — inflating constraint count.

CCS represents high-degree constraints natively. a hash round (degree 7) costs only field operations in the [[SuperSpartan]] prover — no cryptographic cost increase over degree-1 constraints. the Poseidon2 rounds are cheap in the IOP layer.

## CCS and accumulation

for unbounded programs the nox machine becomes one uniform step relation — one CCS for one reduction step (phase 3, in progress). every step yields Reed–Solomon evaluation claims, and hash-based accumulation (ARC/WARP-style) folds those claims into an accumulator of fixed size, decided by one WHIR opening. the same constraint language serves a single statement (the succinct and zk profiles) and every step of a long computation. folding committed CCS instances by homomorphism, as the 0.3/0.4 design tried, needs a homomorphic commitment that a hash does not give; that path is retired as unsound.

see [[zheng]] for the proof system, [[SuperSpartan]] for the IOP, [[stark]] for the general theory