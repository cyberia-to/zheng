---
title: "zheng-2: dual-algebra proof architecture"
status: draft
date: 2026-03-18
depends: [algebraic-extraction.md, folding-first.md, proof-carrying.md, gravity-commitment.md, tensor-compression.md, binius-pcs.md, brakedown-pcs.md, ring-aware-fhe.md, universal-accumulator.md, gpu-prover.md]
---

# zheng-2

the next-generation proof architecture for [[cyber]]. two PCS backends (WHIR/Brakedown for Goldilocks, Binius for F₂) over one field-generic IOP (SuperSpartan + sumcheck + HyperNova). hemera is the only hash. 14 nox languages map to 2 provers. cross-algebra composition via universal CCS folding.

## targets

```
                        zheng-1 (Whirlaway)     zheng-2 + hemera-2      improvement     source
proof size (128-bit):   157 KiB                 1-5 KiB                 30-150×         algebraic-extraction → brakedown
verification:           1.0 ms                  10-50 μs                20-100×         gravity-commitment
recursive step:         70K constraints         30 field ops            2,300×          folding-first
prover memory:          O(N)                    O(√N)                   √N ×            tensor-compression
prover time:            O(N log N)              O(N) streaming          log N ×         tensor-compression
proving latency:        separate step           zero                    ∞ ×             proof-carrying
GPU throughput:         CPU only                45-100× on commodity    45-100×         gpu-prover
binary workloads:       32-64× overhead         native (1 constraint)   32-64×          binius-pcs
FHE bootstrapping:      catastrophic            native (ring-aware)     orders of mag   ring-aware-fhe
light client:           full chain replay       200 bytes, one verify   ∞ ×             universal-accumulator
per-cyberlink (bbg):    ~94K constraints        ~3K constraints         30×             algebraic-nmt
```

## architecture

```
zheng-2
├── IOP layer (field-generic, shared)
│   ├── SuperSpartan          CCS constraint system
│   ├── sumcheck              exponential sum reduction
│   └── HyperNova             folding + composition
│
├── PCS layer (field-specific, two backends)
│   ├── WHIR (Goldilocks)     Reed-Solomon + Merkle (zheng-1 compatible)
│   ├── Brakedown (Goldilocks) expander-graph codes, Merkle-free (target)
│   └── Binius (F₂ tower)     binary Reed-Solomon with packing
│
├── hash layer
│   └── hemera                one hash, universal
│                             Merkle + Fiat-Shamir for all PCS backends
│                             never proved inside binary circuits
│
├── constraint encodings (per-language)
│   ├── generic AIR           nox patterns 0-16
│   ├── ring-structured       R_q operations (Wav, FHE)
│   └── binary                F₂ patterns (Bt)
│
├── jet libraries (per-language)
│   ├── verifier jets         hash, poly_eval, merkle_verify, fri_fold, ntt
│   ├── fhe_bootstrap jets    ntt_batch, key_switch, gadget_decomp, noise_track
│   └── per-language jets     14 languages × dedicated jet sets
│
└── composition
    └── universal accumulator  folds ALL proof types into one constant-size object
```

## two PCS backends

### Goldilocks path

12 of 14 nox languages encode as F_p constraints:

| language | algebra | constraint type |
|---|---|---|
| Tri | F_{p^n} field tower | native field arithmetic |
| Tok | UTXO conservation | field arithmetic + hemera membership |
| Arc | category theory | tree traversal + hemera hashing |
| Seq | partial order | structural comparisons |
| Inf | Horn clauses | unification + resolution |
| Bel | g on Δ^n | fixed-point Bayes |
| Ren | G(p,q,r) shapes | fixed-point geometry |
| Dif | (M, g) manifolds | discretized derivatives |
| Sym | (M, ω) dynamics | Hamiltonian integration |
| Wav | R_q convolution | NTT multiply (ring-aware jets) |
| Ten | contraction (full-precision) | matrix multiply |
| Rs | Z/2^n words (arithmetic-heavy) | word arithmetic + range checks |

PCS options:
- **WHIR** (near-term): Reed-Solomon + hemera Merkle. proof size 60-157 KiB → 5-12 KiB with algebraic extraction
- **Brakedown** (target): expander-graph encoding, Merkle-free. proof size ~1-5 KiB. shifts bottleneck from hemera to nebu

### binary path

2 of 14 languages encode as F₂ constraints:

| language | algebra | constraint type |
|---|---|---|
| Bt | F₂ tower | native binary (XOR=add, AND=mul) |
| Ten | contraction (quantized) | 1-4 bit matrix multiply |

PCS: **Binius** over F₂ tower fields with hemera Merkle commitment externally.

Rs (words) can go either way depending on workload — compiler decides.

### why two, not one

| operation | F_p cost | F₂ cost | ratio |
|---|---|---|---|
| AND | ~32 constraints | 1 constraint | 32× |
| XOR | ~32 constraints | 1 constraint | 32× |
| lt | ~64 constraints | ~1 constraint | 64× |
| field multiply | 1 constraint | ~64 constraints | 0.016× |

binary wins 32-64× for bitwise. Goldilocks wins 64× for arithmetic. one PCS cannot serve both efficiently.

## hemera: one hash

hemera is the ONLY hash in the entire stack. both PCS backends use it:

- **WHIR**: hemera Merkle tree over Goldilocks polynomial evaluations
- **Brakedown**: hemera not needed for commitment (field-ops only), used for Fiat-Shamir
- **Binius**: hemera Merkle tree over packed binary evaluations (bytes in, bytes out — field-agnostic)
- **Fiat-Shamir**: hemera sponge for all backends. challenges squeezed as bytes, interpreted as target field elements

recursion boundary: binary proofs are NEVER verified inside binary circuits. verification crosses to Goldilocks where hemera is native (~736 constraints per permutation with hemera-2). the recursion topology:

```
binary execution → binary proof (hemera external)
                        ↓
    verify in F_p circuit (hemera native, ~736 constraints)
                        ↓
    fold into universal accumulator (Goldilocks)
```

### hemera-2 contribution

hemera-2 (32-byte output, 24 rounds, x⁻¹ partial rounds):

```
                        hemera-1        hemera-2        improvement
rounds per hash:        72              24              3×
constraints/perm:       ~1,200          ~736            1.6×
fold steps per hash:    72              24              3×
output size:            64 bytes        32 bytes        2×
tree node cost:         2 permutations  1 permutation   2×
MPC depth:              192             40              5.4×
FHE noise:              192 sequential  40 sequential   5.4×
```

## cross-algebra composition

### universal CCS

a single CCS instance with algebra selectors:

```
universal_ccs = {
  sel_Fp:   1 for Goldilocks rows, 0 otherwise
  sel_F2:   1 for binary rows, 0 otherwise
  sel_ring: 1 for ring-structured rows (Wav/FHE), 0 otherwise
}
```

### HyperNova folding across algebras

```
fold(acc, goldilocks_instance)  → acc'    (~30 F_p ops + 1 hemera)
fold(acc', binary_instance)     → acc''   (~30 F_p ops + 1 hemera)
fold(acc'', ring_instance)      → acc'''  (~30 F_p ops + 1 hemera)

one accumulator, all algebras
decider: one proof, 10-50 μs verification
```

boundary cost per cross-algebra fold: ~766 F_p constraints (30 field ops + 1 hemera-2 hash). for 32-layer quantized neural net inference: 32 × 766 = ~24.5K F_p constraints. negligible vs millions of binary execution constraints.

## ring-aware FHE proving

with mudra choosing q = Goldilocks ([[goldilocks-fhe]]), R_q operations are native nebu NTT. the Wav language provides ring-structured CCS encodings and dedicated jets:

```
FHE bootstrapping phases:
  gadget decomposition → Bt (Binius)         binary bit-splitting
  blind rotation       → Wav (WHIR/ring)     batched NTT multiply
  key switching        → Ten (WHIR)          matrix-vector
  modulus switching    → Tri (WHIR)          field rescaling

ring-aware jets:
  ntt_batch:      batch n polynomial multiplies (log(n) savings on commitment)
  key_switch:     automorphism as permutation argument (n/log(n) savings)
  gadget_decomp:  delegate binary decomposition to Binius
  noise_track:    running noise accumulator (check once at bootstrap boundary)
```

hemera under FHE: hemera-2's reduced multiplicative depth (40 vs 192) means 5.4× less noise for homomorphic hash evaluation.

## proposals (integrated)

zheng-2 integrates 10 standalone proposals across four areas:

### proof size

| proposal | target | mechanism |
|----------|--------|-----------|
| [[algebraic-extraction]] | 157 KiB → 5-12 KiB | batch algebraic opening replaces Merkle paths |
| [[brakedown-pcs]] | 157 KiB → 1-5 KiB | Merkle-free PCS via expander-graph codes |
| [[gravity-commitment]] | verification ∝ importance | mass-weighted polynomial encoding by π |

algebraic extraction is near-term (applies to WHIR). Brakedown supersedes it long-term by eliminating Merkle trees entirely. gravity commitment makes high-π particles cheaper to verify regardless of PCS backend.

### composition and recursion

| proposal | target | mechanism |
|----------|--------|-----------|
| [[folding-first]] | 70K constraints → 30 field ops | HyperNova folding at every level |
| [[proof-carrying]] | zero proving latency | per-step folding during nox execution |
| [[universal-accumulator]] | one ~200 byte proof for everything | fold all proof types into one object |

folding-first reduces block proving 20× and epoch composition 1000×. proof-carrying eliminates the separate proving phase. universal accumulator extends folding to all obligations (signals + state + LogUp + DAS + VDF). light client: download 200 bytes, verify once, full chain confidence.

### prover performance

| proposal | target | mechanism |
|----------|--------|-----------|
| [[tensor-compression]] | O(√N) memory, O(N) streaming | tensor decomposition of structured traces |
| [[gpu-prover]] | 45-100× throughput | full pipeline in VRAM, zero PCIe transfers |

tensor compression enables mobile proving. GPU prover handles foculus π computation and proof generation on one device.

### binary and domain-specific

| proposal | target | mechanism |
|----------|--------|-----------|
| [[binius-pcs]] | 32-64× cheaper bitwise ops | F₂ tower native PCS with hemera external |
| [[ring-aware-fhe]] | native TFHE bootstrapping | ring-structured CCS + dedicated jets |

binius-pcs serves Bt and quantized Ten/Rs workloads (AI inference, tri-kernel SpMV). ring-aware-fhe proves FHE bootstrapping across 4 phases (gadget_decomp → blind_rotation → key_switch → mod_switch) using existing Wav/Bt/Ten/Tri languages.

## dependency graph

```
nebu  (Goldilocks F_p)──→ hemera (Poseidon2) ──→ zheng-2
                                                    │
kuro  (F₂ towers)    ──────────────────────────────→│
                                                    │
                                              ┌─────┴──────┐
                                              │            │
                                         WHIR/Brakedown  Binius
                                         (Goldilocks)    (F₂)
                                              │            │
                                              └─────┬──────┘
                                                    │
                                              SuperSpartan
                                              sumcheck
                                              HyperNova
                                                    │
                                              universal CCS
                                              universal accumulator
                                                    │
                                              one hemera hash
```

## language → prover mapping

```
14 languages → 14 algebras → 14 jet libraries → 2 fields → 2 PCS → 1 IOP → 1 hash

Goldilocks (WHIR/Brakedown): Tri, Tok, Arc, Seq, Inf, Bel, Ren, Dif, Sym, Wav, Rs*, Ten*
Binary (Binius):              Bt, Ten*, Rs*

* = compiler decides based on workload
```

## migration path

```
phase 1: algebraic extraction on WHIR         (157 KiB → 5-12 KiB)
phase 2: folding-first composition            (block proving 20×, epoch 1000×)
phase 3: Binius PCS backend + kuro            (binary workloads 32-64× cheaper)
phase 4: proof-carrying computation           (zero proving latency)
phase 5: ring-aware FHE jets                  (native FHE bootstrapping)
phase 6: Brakedown PCS replaces WHIR          (Merkle-free, 1-5 KiB proofs)
phase 7: gravity commitment                   (power-law verification cost)
phase 8: tensor trace compression             (O(√N) memory, mobile provers)
phase 9: universal accumulator                (one proof for everything)
phase 10: GPU-native pipeline                 (45-100× throughput)
```

## open questions

1. **Brakedown expander construction**: which family works best for Goldilocks? concrete security parameter vs expansion tradeoff
2. **cross-algebra folding soundness**: universal CCS with selectors — does folding heterogeneous instances preserve HyperNova security?
3. **Binius + hemera integration**: concrete packed trace layout for F₂ with hemera Merkle externally
4. **ring-aware CCS formalization**: R_q operations as structured CCS matrices — where exactly do the batching savings manifest?
5. **gravity weight stability**: re-commitment when π changes significantly
6. **tensor rank of real traces**: empirical validation on cyberlink, inference, and tri-kernel workloads
7. **GPU Fiat-Shamir**: sequential hemera sponge on GPU — latency impact for long transcripts

see [[hemera-2]] for hash upgrade, [[algebra-polymorphism]] for nox instantiation, [[goldilocks-fhe]] for FHE parameters
