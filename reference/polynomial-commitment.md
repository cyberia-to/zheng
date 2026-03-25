---
tags: cyber, computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: polynomial commitments, polynomial commitment scheme, WHIR polynomial commitment, WHIR polynomial commitments, FRI polynomial commitment, FRI polynomial commitments
diffusion: 0.0002813632881429418
springs: 0.0010068991492176759
heat: 0.0007856657208519698
focus: 0.00059988453300716
gravity: 5
density: 1.89
---
# polynomial commitment

a cryptographic primitive that allows a prover to commit to a polynomial and later prove evaluations at specific points. in [[cyber]], the primary PCS is [[Brakedown]] over the [[Goldilocks field]] — expander-graph linear codes, O(N) commitment, O(log N + λ) proof size via recursive opening, zero Merkle trees. one [[hemera]] call for the binding hash. no trusted setup, no pairing-based curves.

zheng-2 supports two PCS backends over one field-generic IOP ([[SuperSpartan]] + [[sumcheck]] + [[HyperNova]]):
- **Brakedown** (Goldilocks) — target PCS. Merkle-free, field-op dominated
- **Binius** (F₂ tower) — binary-native PCS for bitwise workloads
- WHIR (Goldilocks) — legacy/bootstrap PCS, retained for compatibility. see [[WHIR]]

## the primitive

```
COMMIT:   C = Brakedown_commit(P)
          commit to multilinear polynomial P
          C = encoded vector via expander graph (field ops only)
          binding: one hemera hash of the encoded vector

OPEN:     proof = Brakedown_open(P, r)
          prove that P(r) = v for evaluation point r
          recursive: commit the √N opening elements with Brakedown, recurse
          log log N levels until opening fits in λ elements
          proof size: O(log N + λ) field elements ≈ ~1.3 KiB at N=2²⁰

VERIFY:   Brakedown_verify(C, r, v, proof) → accept/reject
          check matrix-vector product consistency at each recursion level
          cost: O(λ log log N) field operations ≈ ~660 field ops ≈ ~5 μs
```

in multilinear mode, Brakedown commits the entire [[nox]] execution trace as a single polynomial. the [[SuperSpartan]] IOP reduces all AIR constraint checks to one evaluation at one random point, which Brakedown opens. see [[zheng]] for the full pipeline.

## Brakedown encoding

the expander graph E = (L, R, edges) with |L| = N, |R| = c·N, left-degree d:

```
encode(polynomial coefficients v ∈ F^N):
  w = E · v        (sparse matrix-vector multiply, O(N) field ops)
  commitment = (w₁, w₂, ..., w_{cN})

  no hashing, no tree construction
  commitment is the encoded vector itself
```

the expander property guarantees: any sufficiently large subset of encoded positions determines the original polynomial. this is the distance property that replaces Reed-Solomon's algebraic distance.

### Goldilocks compatibility

Brakedown requires:
1. a finite field with fast arithmetic — Goldilocks (4-5 cycle multiply)
2. an expander graph family — explicit constructions exist (Margulis, Ramanujan)
3. linear-time encoding — sparse matrix multiply over F_p — nebu

the expander graph needs left-degree d ≈ 20-30 for 128-bit security over Goldilocks (|F| ≈ 2^64). each encoding step is d field multiplications per element. total encoding: d × N ≈ 25N field muls. at 5 cycles per mul: ~125N cycles. for N = 2^20: ~130M cycles ≈ ~40 ms on a single core.

## Brakedown opening (recursive)

to prove f(r) = y for evaluation point r:

```
open(f, r):
  1. verifier sends random tensor t = t₁ ⊗ t₂ ⊗ ... ⊗ tₖ
     (k = log N, each tᵢ ∈ F²)
  2. prover computes q = Σᵢ tᵢ · row_i(encoded matrix)
     (one linear combination of encoded rows)
  3. instead of sending q (√N field elements), commit q with Brakedown
  4. recurse: open the commitment to q at the verifier's challenge point
  5. recurse until the opening vector fits in λ elements (security parameter)

  recursion depth: log log N levels
  at each level: one Brakedown commitment + one tensor reduction
  final level: send ≤ λ field elements directly

proof size: O(log N + λ) field elements ≈ ~1.3 KiB at N=2²⁰
```

### recursive open/verify protocol

```
RECURSIVE_OPEN(C₀, f, r):
  level 0: q₀ = tensor_reduce(f, r)           // √N elements
            C₁ = Brakedown_commit(q₀)          // commit the opening
  level 1: q₁ = tensor_reduce(q₀, r₁)         // N^{1/4} elements
            C₂ = Brakedown_commit(q₁)
  ...
  level d: q_d has ≤ λ elements               // d = log log N
            send q_d directly

  proof = (C₁, C₂, ..., C_d, q_d)

RECURSIVE_VERIFY(C₀, r, v, proof):
  for level i = 0..d-1:
    rᵢ = transcript.squeeze()                  // Fiat-Shamir challenge
    check Cᵢ₊₁ consistent with tensor reduction at rᵢ
  check q_d evaluates to v at the composed point
  cost: O(λ) field ops per level × log log N levels = O(λ log log N)
```

## concrete numbers

for N = 2^20 (typical nox trace):

| metric | WHIR (legacy) | Brakedown (target) |
|---|---|---|
| proof size | 157 KiB | ~2 KiB (sumcheck ~0.5 KiB + eval ~0.3 KiB + PCS opening ~1.3 KiB) |
| commit time | O(N log N) hashes | O(N) field ops |
| verify time | ~1 ms (hash-dominated) | ~5 μs (field-dominated) |
| verifier constraints | ~70K (with jets) | ~8K |
| prover bottleneck | hemera hashing | nebu field arithmetic |

## stack impact

**hemera** collapses to ~3 calls per execution: (1) domain separation wrapper for noun identity, (2) Fiat-Shamir seed, (3) Brakedown binding hash (internal). PCS handles all bulk commitment — state, proofs, and noun identity. hemera is the trust anchor, not the hot path.

**nebu** becomes the proving bottleneck. the expander-graph encoding is sparse matrix-vector multiply over Goldilocks — exactly nebu's strength. SIMD vectorization of nebu field ops becomes the highest-leverage optimization.

**recursive verification** drops from ~70K constraints to ~8K. proof-carrying computation becomes nearly free — the fold overhead per step is ~30 field ops.

## three roles of PCS

Brakedown PCS serves three roles in [[cyber]] — all using the same primitive:

```
1. PROOF COMMITMENT
   commit to nox execution trace (multilinear polynomial)
   SuperSpartan verifies constraints via sumcheck
   HyperNova folds into accumulator

2. STATE COMMITMENT
   BBG_poly: 10 public evaluation dimensions
   A(x): commitment polynomial (private records)
   N(x): nullifier polynomial (spent records)
   BBG_root = H(commit(BBG_poly) ‖ commit(A) ‖ commit(N))

3. NOUN IDENTITY (polynomial nouns)
   every nox noun is a multilinear polynomial
   noun identity = hemera(PCS.commit(noun) ‖ domain_tag) — 32 bytes
   axis = PCS opening at binary point — O(1)
   DAS = PCS opening at random position — native erasure coding
```

one PCS. three roles. one security analysis. the same Brakedown machinery commits proofs, authenticates state, and identifies content.

## PCS comparison

| PCS | setup | post-quantum | proof size (128-bit) | verification | verifier constraints |
|---|---|---|---|---|---|
| **Brakedown** | none | yes | ~2 KiB | ~5 μs | ~8K |
| WHIR | none | yes | ~157 KiB | ~1.0 ms | ~70K |
| Binius (F₂) | none | yes | varies | varies | N/A (external) |
| KZG | trusted | no | 48 bytes | ~2.4 ms | — |
| FRI | none | yes | 306 KiB | ~3.9 ms | — |

Brakedown eliminates Merkle trees from the PCS entirely. WHIR's 157 KiB proof was 77% Merkle auth paths (121 KiB) and its 70K verifier constraints were 83% Merkle verification (58K constraints). recursive Brakedown removes both and compresses the O(√N) opening to O(log N + λ) via log log N levels of self-commitment.

## one primitive, one security analysis

[[cyber]] uses polynomial commitments everywhere rather than mixing hash-based structures with algebraic structures. one primitive means one security analysis, one implementation, one mental model. the same Brakedown that commits execution traces also authenticates state, identifies particles, and provides erasure coding for data availability.

see [[WHIR]] for the legacy PCS, [[zheng]] for the proof architecture, [[BBG]] for polynomial state, [[nox]] for polynomial nouns, [[polynomial nouns]] for the research