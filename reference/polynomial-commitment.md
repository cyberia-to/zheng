---
tags: cyber, computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: polynomial commitments, polynomial commitment scheme, Brakedown polynomial commitment
diffusion: 0.0002813632881429418
springs: 0.0010068991492176759
heat: 0.0007856657208519698
focus: 0.00059988453300716
gravity: 5
density: 1.89
---
# polynomial commitment

a cryptographic primitive that allows a prover to commit to a polynomial and later prove evaluations at specific points. the PCS is recursive [[Brakedown]] over the [[Goldilocks field]] — expander-graph linear codes, O(N) commitment, O(log N + lambda) proof size via recursive opening, zero Merkle trees. one [[hemera]] call for the binding hash. no trusted setup, no pairing-based curves.

two PCS backends over one field-generic IOP ([[SuperSpartan]] + [[sumcheck]] + [[HyperNova]]):
- **Brakedown** (Goldilocks) — primary PCS. Merkle-free, field-op dominated
- **Binius** (F2 tower) — binary-native PCS for bitwise workloads

## the primitive

```
COMMIT:   C = Brakedown_commit(P)
          commit to multilinear polynomial P
          C = encoded vector via expander graph (field ops only)
          binding: one hemera hash of the encoded vector

OPEN:     proof = Brakedown_open(P, r)
          prove that P(r) = v for evaluation point r
          recursive: commit the sqrt(N) opening elements with Brakedown, recurse
          log log N levels until opening fits in lambda elements
          proof size: O(log N + lambda) field elements ~ ~1.3 KiB at N=2^20

VERIFY:   Brakedown_verify(C, r, v, proof) -> accept/reject
          check matrix-vector product consistency at each recursion level
          cost: O(lambda log log N) field operations ~ ~660 field ops ~ ~5 us
```

in multilinear mode, Brakedown commits the entire [[nox]] execution trace as a single polynomial. the [[SuperSpartan]] IOP reduces all AIR constraint checks to one evaluation at one random point, which Brakedown opens. see [[zheng]] for the full pipeline.

## Brakedown encoding

the expander graph E = (L, R, edges) with |L| = N, |R| = c*N, left-degree d:

```
encode(polynomial coefficients v in F^N):
  w = E * v        (sparse matrix-vector multiply, O(N) field ops)
  commitment = (w_1, w_2, ..., w_{cN})

  no hashing, no tree construction
  commitment is the encoded vector itself
```

the expander property guarantees: any sufficiently large subset of encoded positions determines the original polynomial. this is the distance property that replaces Reed-Solomon's algebraic distance.

### Goldilocks compatibility

Brakedown requires:
1. a finite field with fast arithmetic — Goldilocks (4-5 cycle multiply)
2. an expander graph family — explicit constructions exist (Margulis, Ramanujan)
3. linear-time encoding — sparse matrix multiply over F_p — nebu

the expander graph needs left-degree d ~ 20-30 for 128-bit security over Goldilocks (|F| ~ 2^64). each encoding step is d field multiplications per element. total encoding: d * N ~ 25N field muls. at 5 cycles per mul: ~125N cycles. for N = 2^20: ~130M cycles ~ ~40 ms on a single core.

## Brakedown opening (recursive)

to prove f(r) = y for evaluation point r:

```
open(f, r):
  1. verifier sends random tensor t = t_1 (x) t_2 (x) ... (x) t_k
     (k = log N, each t_i in F^2)
  2. prover computes q = sum_i t_i * row_i(encoded matrix)
     (one linear combination of encoded rows)
  3. instead of sending q (sqrt(N) field elements), commit q with Brakedown
  4. recurse: open the commitment to q at the verifier's challenge point
  5. recurse until the opening vector fits in lambda elements (security parameter)

  recursion depth: log log N levels
  at each level: one Brakedown commitment + one tensor reduction
  final level: send <= lambda field elements directly

proof size: O(log N + lambda) field elements ~ ~1.3 KiB at N=2^20
```

### recursive open/verify protocol

```
RECURSIVE_OPEN(C_0, f, r):
  level 0: q_0 = tensor_reduce(f, r)           // sqrt(N) elements
            C_1 = Brakedown_commit(q_0)          // commit the opening
  level 1: q_1 = tensor_reduce(q_0, r_1)         // N^{1/4} elements
            C_2 = Brakedown_commit(q_1)
  ...
  level d: q_d has <= lambda elements               // d = log log N
            send q_d directly

  proof = (C_1, C_2, ..., C_d, q_d)

RECURSIVE_VERIFY(C_0, r, v, proof):
  for level i = 0..d-1:
    r_i = transcript.squeeze()                  // Fiat-Shamir challenge
    check C_{i+1} consistent with tensor reduction at r_i
  check q_d evaluates to v at the composed point
  cost: O(lambda) field ops per level * log log N levels = O(lambda log log N)
```

## concrete numbers

for N = 2^20 (typical nox trace):

| metric | value |
|---|---|
| proof size | ~2 KiB (sumcheck ~0.5 KiB + eval ~0.3 KiB + PCS opening ~1.3 KiB) |
| commit time | O(N) field ops |
| verify time | ~5 us (field-dominated) |
| verifier constraints | ~825 (CCS jet + batch + algebraic FS) |
| prover bottleneck | nebu field arithmetic |

## stack impact

**hemera** collapses to ~3 calls per execution: (1) domain separation wrapper for noun identity, (2) Fiat-Shamir seed, (3) Brakedown binding hash (internal). PCS handles all bulk commitment — state, proofs, and noun identity. hemera is the trust anchor, not the hot path.

**nebu** is the proving bottleneck. the expander-graph encoding is sparse matrix-vector multiply over Goldilocks — exactly nebu's strength. SIMD vectorization of nebu field ops is the highest-leverage optimization.

**recursive verification** at ~825 constraints. proof-carrying computation is nearly free — the fold overhead per step is ~30 field ops.

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
   BBG_root = H(commit(BBG_poly) || commit(A) || commit(N))

3. NOUN IDENTITY (polynomial nouns)
   every nox noun is a multilinear polynomial
   noun identity = hemera(PCS.commit(noun) || domain_tag) — 32 bytes
   axis = PCS opening at binary point — O(1)
   DAS = PCS opening at random position — native erasure coding
```

one PCS. three roles. one security analysis. the same Brakedown machinery commits proofs, authenticates state, and identifies content.

## one primitive, one security analysis

[[cyber]] uses polynomial commitments everywhere rather than mixing hash-based structures with algebraic structures. one primitive means one security analysis, one implementation, one mental model. the same Brakedown that commits execution traces also authenticates state, identifies particles, and provides erasure coding for data availability.

see [[zheng]] for the proof architecture, [[BBG]] for polynomial state, [[nox]] for polynomial nouns, [[polynomial nouns]] for the research
