---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: sumcheck protocol
diffusion: 0.00024078878226632726
springs: 0.00036111148333910204
heat: 0.00035045605749663074
focus: 0.0002988190476342166
gravity: 10
density: 0.81
---
# sumcheck

an interactive proof protocol that reduces verifying a sum over exponentially many terms to checking a single evaluation. Lund, Fortnow, Karloff, Nisan (1992). the engine inside [[zheng]] and [[SuperSpartan]].

## the protocol

given a k-variate polynomial f, prove that the sum over the boolean hypercube equals a claimed value:

```
claim: Σ_{x ∈ {0,1}ᵏ} f(x₁, ..., x_k) = T

round i (for i = 1, ..., k):
  prover sends univariate polynomial gᵢ(Xᵢ)
  verifier checks: gᵢ(0) + gᵢ(1) = previous claim
  verifier sends random challenge rᵢ
  new claim: gᵢ(rᵢ)

after k rounds:
  final claim = f(r₁, ..., r_k)
  verifier checks this single evaluation (via PCS opening)
```

2^k terms reduced to k rounds. total verifier work: O(k) field operations + one polynomial evaluation check.

## cost

```
prover:   O(2^k) field operations — linear in the summation domain
verifier: O(k) field operations + one PCS opening check
rounds:   k (one per variable)
```

for a [[nox]] execution trace with 2ⁿ steps and 2ᵐ registers, k = n + m. the sumcheck prover is linear in the trace size. the verifier's work is logarithmic.

## round polynomial construction

at each round the prover constructs a univariate polynomial that sums out one variable while keeping earlier variables pinned to verifier challenges.

### general algorithm

at round i, variables x₁, ..., x_{i-1} are fixed to challenges r₁, ..., r_{i-1}. the prover computes:

```
gᵢ(Xᵢ) = Σ_{x_{i+1}, ..., x_k ∈ {0,1}} f(r₁, ..., r_{i-1}, Xᵢ, x_{i+1}, ..., x_k)
```

gᵢ is a univariate polynomial of degree at most d, where d is the constraint degree of f. the prover determines gᵢ by evaluating it at d + 1 points: Xᵢ = 0, 1, 2, ..., d. these d + 1 evaluations uniquely determine a degree-d polynomial via interpolation.

### SuperSpartan over CCS (degree d = 7, pattern 15)

in [[SuperSpartan]] with CCS constraints of max degree d = 7:

```
each round polynomial gᵢ has degree ≤ 7
prover sends 8 evaluations per round (d + 1 = 8 points determine a degree-7 poly)
verifier checks: gᵢ(0) + gᵢ(1) = claimᵢ₋₁
total prover work per round: O(2^{k-i}) evaluations of the constraint polynomial
```

across k rounds the verifier performs 8k field additions for consistency checks, plus one final PCS opening.

### optimization: bookkeeping tables

the prover maintains a table of partial sums that halves in size each round:

```
round 1: table has 2^k entries    → compute g₁ in O(2^k) work
round 2: table has 2^{k-1} entries → compute g₂ in O(2^{k-1}) work
  ...
round i: table has 2^{k-i} entries → compute gᵢ in O(2^{k-i}) work
  ...
round k: table has 1 entry        → compute g_k in O(1) work
```

after computing gᵢ, the prover receives challenge rᵢ and folds the table: each pair of entries (one for xᵢ = 0, one for xᵢ = 1) is combined as (1 - rᵢ) · entry₀ + rᵢ · entry₁. total work across all k rounds: O(2^k) + O(2^{k-1}) + ... + O(1) = O(2^k) = O(N), linear in the summation domain size.

## role in cyber

in the [[zheng]] pipeline, sumcheck replaces the zerofier division step of classical univariate starks. [[SuperSpartan]] uses sumcheck to verify AIR constraints: the sum of constraint polynomials over all trace rows must be zero. sumcheck reduces this to evaluating the trace polynomial at one random point, which [[Brakedown]] opens.

sumcheck also appears in LogUp lookup arguments for cross-index consistency in the [[cybergraph]] (see [[bbg-integration]]).

see [[zheng]] for the full proof pipeline, [[SuperSpartan]] for the IOP, [[polynomial-commitment]] for the PCS