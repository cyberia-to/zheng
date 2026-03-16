---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: SuperSpartan IOP
---
# SuperSpartan

an Interactive Oracle Proof (IOP) for Customizable Constraint Systems ([[CCS]]). Setty, Thaler, Wahby (2023). ePrint 2023/552.

## CCS definition

a CCS instance is a tuple (M₁, ..., M_t, S₁, ..., S_q, c₁, ..., c_q, m, n, l):

```
matrices:     M₁, ..., M_t ∈ F^{m×n}    (sparse)
index sets:   S₁, ..., S_q ⊆ [t]
coefficients: c₁, ..., c_q ∈ F
witness:      z ∈ F^n   (z = (1, x, w) where x is public input, w is private witness)

satisfiability: Σⱼ cⱼ · ∏_{i ∈ Sⱼ} Mᵢ · z = 0
```

special cases:

| system | parameters | degree |
|---|---|---|
| R1CS | t=3, q=2, S₁={1,2}, S₂={3}, c₁=1, c₂=−1 | 2 |
| Plonkish | selector matrices as M | custom |
| AIR | shifted-row matrices as M | any |

## protocol

```
SETUP: none

PROVER(CCS instance I, witness w):
  1. z = (1, x, w)
  2. encode z as multilinear polynomial ẑ: F^{log n} → F
  3. commit: C_ẑ = PCS_commit(ẑ)
  4. for each matrix Mᵢ:
       compute ûᵢ(y) = Σ_x M̃ᵢ(y, x) · ẑ(x)    // multilinear extension of Mᵢ · z
  5. receive random r ∈ F^{log m} from verifier
  6. define g(x) = Σⱼ cⱼ · ∏_{i ∈ Sⱼ} ûᵢ(x)    // constraint polynomial
  7. run sumcheck on: Σ_{x ∈ {0,1}^{log m}} eq(r, x) · g(x) = 0
     → reduces to evaluation at random point s
  8. for each ûᵢ: open ûᵢ(s) via sumcheck on Mᵢ definition
     → reduces to evaluation of ẑ at random point t
  9. open PCS_open(ẑ, t) → v, π

VERIFIER(CCS instance I, commitment C_ẑ, proof):
  1. sample r ∈ F^{log m}
  2. verify outer sumcheck (step 7): k = log(m) rounds
     for each round i:
       check gᵢ(0) + gᵢ(1) = claim_{i-1}
       send challenge rᵢ
  3. at sumcheck output point s:
     check claimed evaluation = eq(r, s) · Σⱼ cⱼ · ∏_{i ∈ Sⱼ} claimed_ûᵢ(s)
  4. verify inner sumchecks (step 8): reduce each ûᵢ(s) to ẑ(t)
  5. verify PCS_verify(C_ẑ, t, v, π)
```

the outer sumcheck (step 7) verifies constraint satisfaction over all m rows. the inner sumchecks (step 8) verify the matrix-vector products. together they reduce m × n constraint checks to one PCS opening.

## cost

| phase | prover | verifier |
|---|---|---|
| multilinear extensions (step 4) | O(N) field ops per matrix | — |
| outer sumcheck (step 7) | O(N) field ops | O(log m) field ops |
| inner sumchecks (step 8) | O(N) field ops per matrix | O(log n) field ops |
| PCS open/verify | depends on PCS | depends on PCS |
| total (IOP only) | O(t · N) field ops | O(t · log N) field ops |

where N = max(m, n) = trace size. prover is linear. verifier is logarithmic.

constraint degree affects only field operation count in the prover (step 6), not cryptographic operations. degree-7 constraints ([[hemera]] rounds) cost 7× the field multiplications of degree-1 constraints but require the same number of PCS operations.

## instantiation in zheng

| parameter | value |
|---|---|
| field | [[Goldilocks field]] (p = 2^64 − 2^32 + 1) |
| PCS | [[WHIR]] (multilinear mode) |
| m | 2^n trace rows (up to 2^32) |
| n | 16 registers (2^4 columns) |
| t | number of constraint matrices (pattern-dependent) |
| max degree | 7 (pattern 15: Poseidon2 round) |
| Fiat-Shamir | [[hemera]] sponge (see [[transcript]]) |

the CCS matrices are sparse: each [[nox]] pattern touches at most 6 registers per row. sparsity determines the constant factor in the O(t · N) prover cost.

## soundness

| parameter | value |
|---|---|
| IOP soundness error | O(max_degree · log(m) / |F|) per sumcheck |
| with Goldilocks (|F| ≈ 2^64) | negligible for practical trace sizes |
| composition with WHIR | total soundness = IOP error + PCS soundness error |

see [[sumcheck]] for the core protocol, [[whir]] for the PCS, [[constraints]] for CCS encoding of nox patterns, [[CCS]] for the constraint framework, [[whirlaway]] for the full architecture
