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

a cryptographic primitive that allows a prover to commit to a polynomial and later prove evaluations at specific points. in [[cyber]], the primary PCS is [[Brakedown]] over the [[Goldilocks field]] — expander-graph linear codes, O(N) commitment, O(sqrt(N)) proof size, zero Merkle trees. one [[hemera]] call for the binding hash. no trusted setup, no pairing-based curves.

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
          proof = linear combination of encoded rows (O(√N) field elements)

VERIFY:   Brakedown_verify(C, r, v, proof) → accept/reject
          check matrix-vector product consistency
          cost: O(√N) field operations
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

## Brakedown opening

to prove f(r) = y for evaluation point r:

```
open(f, r):
  1. verifier sends random tensor t = t₁ ⊗ t₂ ⊗ ... ⊗ tₖ
     (k = log N, each tᵢ ∈ F²)
  2. prover computes q = Σᵢ tᵢ · row_i(encoded matrix)
     (one linear combination of encoded rows)
  3. prover sends q (√N field elements)
  4. verifier checks: q is consistent with commitment
     and q evaluates to y at the tensor point

proof size: O(√N) field elements = O(√N × 8) bytes
```

## concrete numbers

for N = 2^20 (typical nox trace):

| metric | WHIR (legacy) | Brakedown (target) |
|---|---|---|
| proof size | 157 KiB | ~8 KiB |
| commit time | O(N log N) hashes | O(N) field ops |
| verify time | ~1 ms (hash-dominated) | ~30 μs (field-dominated) |
| verifier constraints | ~70K (with jets) | ~12K |
| prover bottleneck | hemera hashing | nebu field arithmetic |

## stack impact

**hemera** becomes less critical for proving. still essential for BBG state (NMT trees, content addressing) and Fiat-Shamir, but no longer in the proof internals. the optimization target shifts from "faster hashing" to "faster field ops."

**nebu** becomes the proving bottleneck. the expander-graph encoding is sparse matrix-vector multiply over Goldilocks — exactly nebu's strength. SIMD vectorization of nebu field ops becomes the highest-leverage optimization.

**recursive verification** drops from ~70K constraints to ~12K. proof-carrying computation becomes nearly free — the fold overhead per step is ~30 field ops + 1 hemera hash.

## why polynomial commitments

the [[cybergraph]] needs to prove membership ("this edge belongs to neuron N's edge set") and completeness ("these are ALL edges for neuron N"). polynomial commitments handle both efficiently:

| operation | Merkle tree | polynomial commitment |
|---|---|---|
| membership proof | O(log n) hashes, ~9,600 constraints | O(√n), ~500 constraints |
| batch membership (N elements) | N × O(log n), ~9,600 × N | amortized sublinear |
| state root update | O(log n) rehash | O(1) update |
| completeness proof | impossible (standard Merkle) | requires sorted polynomial + NMT |

the batch proof advantage is decisive for transaction verification: a single [[cyberlink]] touches 3 EdgeSets, and a block contains thousands of cyberlinks. batched Brakedown openings make this tractable.

## use in cyber

polynomial commitments appear at two levels of the [[BBG]]:

```
Level 1: NMT (Namespaced Merkle Trees)
  → structural completeness: "these are ALL items in namespace N"
  → uses standard Merkle hashing (hemera)

Level 2: EdgeSets (polynomial commitments via Brakedown)
  → efficient membership: "this edge belongs to this namespace's set"
  → batched openings: sublinear cost for multi-edge proofs
```

each NMT leaf contains an EdgeSet — a Brakedown polynomial commitment to the set of edge hashes belonging to that namespace. the NMT provides completeness guarantees. the polynomial commitment provides efficient membership queries.

## EdgeSet construction

```
EdgeSet for neuron N:
  edges = { e | e.neuron = N }
  edge_hashes = { H_edge(e) | e ∈ edges }

  construct polynomial P_N(x) such that:
    P_N(0) = edge_hashes[0]
    P_N(1) = edge_hashes[1]
    ...
    P_N(k-1) = edge_hashes[k-1]

  EdgeSet commitment: C_N = Brakedown_commit(P_N)
```

## PCS comparison

| PCS | setup | post-quantum | proof size (128-bit) | verification | verifier constraints |
|---|---|---|---|---|---|
| **Brakedown** | none | yes | ~8 KiB | ~30 μs | ~12K |
| WHIR | none | yes | ~157 KiB | ~1.0 ms | ~70K |
| Binius (F₂) | none | yes | varies | varies | N/A (external) |
| KZG | trusted | no | 48 bytes | ~2.4 ms | — |
| FRI | none | yes | 306 KiB | ~3.9 ms | — |

Brakedown eliminates Merkle trees from the PCS entirely. WHIR's 157 KiB proof was 77% Merkle auth paths (121 KiB) and its 70K verifier constraints were 83% Merkle verification (58K constraints). Brakedown removes both.

## one primitive, one security analysis

[[cyber]] uses polynomial commitments everywhere rather than mixing hash-based structures with algebraic structures. one primitive means one security analysis, one implementation, one mental model. the same Brakedown machinery that makes UTXO proofs cheap also handles graph completeness proofs.

see [[WHIR]] for the legacy PCS, [[zheng]] for the proof architecture, [[BBG]] for the graph architecture, [[bbg-integration]] for EdgeSet/NMT/LogUp details