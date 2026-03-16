---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: Weights Help Improving Rate
---
# WHIR

Weights Help Improving Rate. an interactive oracle proof of proximity for constrained Reed-Solomon codes that simultaneously serves as a multilinear polynomial commitment scheme. Arnon, Chiesa, Fenzi, Yogev (EUROCRYPT 2025). ePrint 2024/1586.

## protocol

WHIR provides three operations:

```
WHIR_commit(f) → C
  input:  multilinear polynomial f(x₁, ..., x_k) over Goldilocks
  output: commitment C (hemera Merkle root over evaluation table)
  cost:   O(2^k log 2^k) hemera hashes

WHIR_open(f, r) → (v, π)
  input:  polynomial f, evaluation point r ∈ F^k
  output: value v = f(r), proximity proof π
  cost:   O(2^k) field ops + O(log² 2^k) hemera hashes

WHIR_verify(C, r, v, π) → accept/reject
  input:  commitment C, point r, claimed value v, proof π
  output: accept if f(r) = v and f is close to a degree-bounded polynomial
  cost:   O(log² 2^k) hemera hashes + field ops
```

## verification algorithm

```
WHIR_verify(C, r, v, proof):
  1. init transcript T from C
  2. for each folding round i = 1..log(N):
     a. absorb prover's round message into T
     b. squeeze challenge αᵢ from T
     c. verify Merkle paths for queried positions against round commitment
     d. fold polynomial: combine evaluations using αᵢ as weight
     e. check consistency: folded values match next round's commitment
  3. verify final polynomial is constant (degree 0)
  4. check that the accumulated evaluation equals v at point r
```

each round halves the polynomial's variable count. after log(N) rounds, the polynomial is a constant — verifiable by direct comparison.

## parameters

| parameter | 100-bit security | 128-bit security |
|---|---|---|
| argument size (standalone) | ~101 KiB | ~157 KiB |
| verification time | ~290 μs | ~1.0 ms |
| verifier hashes | ~1,800 | ~2,700 |
| folding rounds | log₂(N) | log₂(N) |
| queries per round | determined by security target | determined by security target |
| field | [[Goldilocks field]] (p = 2^64 − 2^32 + 1) | [[Goldilocks field]] |
| hash | [[hemera]] (Poseidon2) | [[hemera]] (Poseidon2) |

the standalone WHIR argument size (~101 KiB at 100-bit) is larger than the full [[whirlaway]] proof (~60 KiB at 100-bit). the difference: Whirlaway's multilinear encoding and [[SuperSpartan]] sumcheck reduce the WHIR opening to ~58 KiB. see [[whirlaway]] for the composed proof breakdown.

## performance comparison

at d = 2²⁴, 128-bit security:

| scheme | argument size | verifier hashes | verification time |
|---|---|---|---|
| [[FRI]] | 306 KiB | 5,600 | 3.9 ms |
| [[STIR]] | 160 KiB | 2,600 | 3.8 ms |
| WHIR | 157 KiB | 2,700 | 1.0 ms |

at 100-bit security:

| scheme | argument size | verification time | setup |
|---|---|---|---|
| KZG | 48 bytes | 2.4 ms | trusted |
| PST | ~200 bytes | 3.6 ms | trusted |
| BaseFold | 7.95 MiB | 24 ms | none |
| WHIR | 101 KiB | 290 μs | none |

## properties

| property | value |
|---|---|
| trusted setup | none (transparent) |
| post-quantum | yes (hash-only security) |
| dual nature | IOPP (proximity test) + multilinear PCS |
| field | any with large multiplicative subgroup |
| soundness | mutual correlated agreement |

## verification circuit decomposition

inside [[nox]], WHIR_verify decomposes into two jets:

```
merkle_verify(root, leaf, path, index)
  d × 300 constraints per depth-d path

fri_fold(poly_layer, challenge)        // nox jet
  N/2 constraints per folding round
```

full WHIR_verify:

```
1. Fiat-Shamir: derive challenges from transcript
   → hemera hashes (~22 cycles per challenge)

2. per folding round (log(N) rounds):
   a. merkle_verify: check evaluation query paths
   b. fri_fold: fold polynomial with round challenge
   c. sumcheck round: weight polynomial combination (~10 constraints)

3. final check: verify folded polynomial is constant
```

estimated constraints for N = 2^16, 100-bit security:

| component | calls | constraints |
|---|---|---|
| Fiat-Shamir (hemera) | ~16 hashes | ~19,200 |
| merkle_verify | ~50 paths × depth 16 | ~240,000 |
| fri_fold | 16 rounds, geometric sum | ~32,768 |
| sumcheck rounds | 16 | ~160 |
| total | | ~292,000 |

without jets (pure Layer 1): ~2,900,000 constraints (10×).

## design notes

### WHIR-compressed Merkle proofs

standard [[hemera]] Merkle proof for depth 20: 1,280 bytes. WHIR alternative: commit each tree level as a multilinear polynomial, open at queried positions.

```
encoding: f_ℓ(b₁, ..., b_ℓ) = hash of node reached by path bits b₁...b_ℓ
crossover: k > ~80 leaves for depth 20 (below this, standard proofs are smaller)
hybrid:    prover selects mode; verifier accepts both via mode flag
```

open questions: evaluation table layout, root finalization domain separation, hybrid mode protocol.

### incremental commitment updates

EdgeSet polynomial commitments face re-commitment cost when edges are added. with a fixed evaluation domain:

```
insert edge k+1:
  1. evaluate P at new point
  2. update one Merkle leaf
  3. rehash path: log₂(D) × 2 permutations

for D = 2^16: 32 permutations per insertion
vs full re-commit: O(N log N) hashes
```

domain sizing strategy: start at 2^10, double when 75% full. amortized O(1) per insertion.

### composed WHIR_VERIFY jet

a single jet combining merkle_verify + fri_fold + Fiat-Shamir could reduce verification to ~100K constraints (from ~292K). trades ISA complexity for recursion depth. current two-jet decomposition suffices for depths up to ~10.

see [[polynomial-commitment]] for the commitment abstraction, [[sumcheck]] for the weight polynomial mechanism, [[verifier]] for the full zheng verification algorithm, [[whirlaway]] for the architecture
