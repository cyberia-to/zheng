# zheng proposals

design proposals for zheng proof system evolution. [[zheng-2]] is the integrated architecture — all other proposals feed into it.

## architecture

| proposal | status | target |
|----------|--------|--------|
| [[zheng-2]] | draft | dual-algebra proof architecture: 2 PCS, 1 IOP, 1 hash, 14 languages |

## PCS backends

| proposal | status | target |
|----------|--------|--------|
| [[binius-pcs]] | draft | F₂ tower native PCS — 32-64× cheaper bitwise ops |
| [[brakedown-pcs]] | draft | Merkle-free PCS via expander-graph codes — 1-5 KiB proofs |

## proof size and verification

| proposal | status | target |
|----------|--------|--------|
| [[algebraic-extraction]] | accepted | batch algebraic opening — 157 KiB → 5-12 KiB |
| [[gravity-commitment]] | accepted | mass-weighted encoding — verification ∝ importance |

## composition and recursion

| proposal | status | target |
|----------|--------|--------|
| [[folding-first]] | accepted | HyperNova composition — 70K constraints → 30 field ops |
| [[proof-carrying]] | accepted | zero proving latency — proof emerges from computation |
| [[universal-accumulator]] | draft | fold ALL proof types into one ~200 byte object |

## prover optimization

| proposal | status | target |
|----------|--------|--------|
| [[tensor-compression]] | accepted | O(√N) memory, O(N) streaming prover — mobile devices |
| [[gpu-prover]] | draft | full pipeline in VRAM — 45-100× throughput |

## domain-specific

| proposal | status | target |
|----------|--------|--------|
| [[ring-aware-fhe]] | draft | native TFHE bootstrapping — ring-structured CCS + jets |

## combined targets (all proposals)

```
                        zheng-1 (Whirlaway)     zheng-2             improvement
proof size (128-bit):   157 KiB                 1-5 KiB             30-150×
verification:           1.0 ms                  10-50 μs            20-100×
recursive step:         70K constraints          30 field ops        2,300×
prover memory:          O(N)                    O(√N)               √N ×
prover time:            O(N log N)              O(N) streaming      log N ×
proving latency:        separate step           zero (proof-carrying) ∞ ×
binary workloads:       32-64× overhead         native              32-64×
FHE bootstrapping:      catastrophic            native (ring-aware)  orders of magnitude
GPU throughput:         CPU only                45-100× on commodity  45-100×
```

## recommended sequence

```
phase 1:  algebraic extraction      near-term proof size win on existing WHIR
phase 2:  folding-first             20× block proving, 1000× epoch composition
phase 3:  binius-pcs + kuro         binary workloads go native
phase 4:  proof-carrying            zero proving latency
phase 5:  ring-aware-fhe            native FHE bootstrapping
phase 6:  brakedown-pcs             Merkle-free replaces WHIR
phase 7:  gravity-commitment        power-law verification cost
phase 8:  tensor-compression        O(√N) memory, mobile provers
phase 9:  universal-accumulator     one proof for everything
phase 10: gpu-prover               full pipeline on GPU
```

## cross-repo proposals

| proposal | repo | relation to zheng |
|----------|------|-------------------|
| [[algebraic-nmt]] | bbg | polynomial commitment replaces NMT trees — uses zheng PCS |
| [[goldilocks-fhe]] | mudra | q = Goldilocks for FHE — enables ring-aware-fhe |

## lifecycle

| status | meaning |
|--------|---------|
| draft | idea captured, open for discussion |
| accepted | approved — ready to implement |
| rejected | decided against, kept for rationale |
| implemented | done — migrated to relevant spec file |
