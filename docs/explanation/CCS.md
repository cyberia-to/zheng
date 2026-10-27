---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: Customizable Constraint Systems
---
# CCS

Customizable Constraint Systems. a unified constraint framework that generalizes R1CS, Plonkish (PLONK/Halo2), and [[AIR]] into one representation. Setty, Thaler, Wahby (2023).

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

a single statement (profiles 0–3 and the succinct and zk profiles) is one CCS compiled from its program. a run of any length uses the nox machine instead (`specs/machine.md`, envelope profiles 4–6): one uniform row relation, the same for every program — an AIR in the CCS sense, proved by a sumcheck zerocheck, with no univariate quotient. every segment leaves Reed–Solomon evaluation claims, and hash-based accumulation (`accumulate`, WARP-structured with ARC-style out-of-domain samples) folds them into an accumulator of fixed size, decided by one WHIR opening. folding committed CCS instances by homomorphism, as the retired 0.3 design tried, needs a homomorphic commitment that a hash does not give; that path is unsound and survives only behind the cargo feature `legacy`.

see [[zheng]] for the proof system, [[SuperSpartan]] for the IOP, [[stark]] for the general theory