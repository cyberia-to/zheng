---
tags: cyber, cip
crystal-type: process
crystal-domain: cyber
status: draft
diffusion: 0.00010722364868599256
springs: 0.00007019991600688145
heat: 0.00003419142694206788
focus: 0.00008151008453347325
gravity: 0
density: 0
---
# brakedown PCS — Merkle-free polynomial commitment

replace WHIR's Reed-Solomon + Merkle tree commitment with linear-time encodable codes using expander graphs. eliminates Merkle auth paths entirely — the 77% of proof size and 83% of recursive verifier cost. goes beyond [[proof-horizons]] Horizon 1 (algebraic extraction) by removing the tree structure from the PCS altogether.

## current bottleneck

WHIR proof composition (128-bit security):

```
total proof:         157 KiB
  Merkle auth paths: 121 KiB (77%)
  leaf values:        22 KiB (14%)
  round commitments:  14 KiB (9%)

recursive verifier:  70K constraints (with jets)
  Merkle verify:     58K constraints (83%)
  everything else:   12K constraints (17%)
```

Merkle trees dominate both dimensions. algebraic extraction (Horizon 1) reduces this by batching Merkle paths into one algebraic argument (5-12 KiB). Brakedown eliminates the tree entirely.

## the idea

Brakedown (Golovnev et al. 2022) commits to a multilinear polynomial using a linear-time encodable code based on expander graphs instead of Reed-Solomon:

```
WHIR:      commit = RS encode + Merkle tree     O(N log N) hemera hashes
Brakedown: commit = expander encode              O(N) field operations, ZERO hashes

WHIR:      proof = Merkle auth paths            O(log²N × λ) hashes
Brakedown: proof = linear combination + check    O(√N) field elements

WHIR:      verify = Merkle path check           O(log²N × λ) hemera calls
Brakedown: verify = matrix-vector product        O(√N) field operations
```

## encoding

the expander graph E = (L, R, edges) with |L| = N, |R| = c·N, left-degree d:

```
encode(polynomial coefficients v ∈ F^N):
  w = E · v        (sparse matrix-vector multiply, O(N) field ops)
  commitment = (w₁, w₂, ..., w_{cN})

  no hashing, no tree construction
  commitment is the encoded vector itself
```

the expander property guarantees: any sufficiently large subset of encoded positions determines the original polynomial. this is the distance property that replaces Reed-Solomon's algebraic distance.

## opening

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

for N = 2²⁰ (typical nox trace):

| metric | WHIR | algebraic extraction | Brakedown |
|---|---|---|---|
| proof size | 157 KiB | 5-12 KiB | **~8 KiB** |
| commit time | O(N log N) hashes | O(N log N) hashes | **O(N) field ops** |
| verify time | ~1 ms (hash-dominated) | ~50 μs | **~30 μs (field-dominated)** |
| verifier constraints | 70K (with jets) | ~10K | **~5K** |
| prover bottleneck | hemera hashing | hemera hashing | **nebu field arithmetic** |

## stack impact

**hemera** becomes less critical for proving. still essential for BBG state (NMT trees, content addressing) but no longer in the proof internals. the optimization target shifts from "faster hashing" to "faster field ops."

**nebu** becomes the proving bottleneck. the expander-graph encoding is sparse matrix-vector multiply over Goldilocks — exactly nebu's strength. SIMD vectorization of nebu field ops becomes the highest-leverage optimization.

**recursive verification** drops from 70K constraints to ~5K. proof-carrying computation (Horizon 3) becomes nearly free — the fold overhead per step is ~30 field ops + ~5K verifier constraints instead of ~30 field ops + ~70K constraints.

## Goldilocks compatibility

Brakedown requires:
1. a finite field with fast arithmetic → Goldilocks (4-5 cycle multiply)
2. an expander graph family → explicit constructions exist (Margulis, Ramanujan)
3. linear-time encoding → sparse matrix multiply over F_p → nebu

the expander graph needs left-degree d ≈ 20-30 for 128-bit security over Goldilocks (|F| ≈ 2⁶⁴). each encoding step is d field multiplications per element. total encoding: d × N ≈ 25N field muls. at 5 cycles per mul: ~125N cycles. for N = 2²⁰: ~130M cycles ≈ ~40 ms on a single core. comparable to WHIR Merkle construction but without any hashing.

## relation to proof-horizons

Horizon 1 (algebraic extraction) batches Merkle paths into one algebraic argument. Brakedown goes further — no Merkle tree exists to extract from. the two approaches are not competing:

- **near-term**: algebraic extraction on top of WHIR (keeps existing infrastructure, 20× improvement)
- **long-term**: Brakedown replaces WHIR entirely (eliminates hashing from proofs, 30-150× improvement)

both compose with Horizons 2-5 (folding, proof-carrying, gravity, tensor compression).

## open questions

1. **expander graph construction**: which explicit family works best for Goldilocks? Margulis (algebraic, d=8) vs random bipartite (d≈20, probabilistic) vs Ramanujan (optimal expansion, complex construction)
2. **Schwartz-Zippel over Goldilocks**: soundness requires |F| >> degree. Goldilocks |F| ≈ 2⁶⁴. for degree-7 constraints (hemera S-box): 7/2⁶⁴ ≈ 0 — fine. but accumulated over many sumcheck rounds?
3. **batch opening**: WHIR naturally batches (multiple points, one tree). Brakedown batch opening requires tensor product structure — feasible but different interface
4. **GPU parallelism**: sparse matrix multiply is irregular memory access — harder to GPU-accelerate than NTT. may favor CPU for encoding, GPU for other pipeline stages

see [[proof-horizons]] for algebraic extraction, [[zheng-2]] for unified architecture