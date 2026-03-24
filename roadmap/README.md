# zheng roadmap

design proposals for [[zheng]] proof system. see [[zheng-2]] for the integrated architecture.

## status: in reference = proposal is now the canonical spec

## architecture

| proposal | in reference? | target |
|----------|--------------|--------|
| [[zheng-2]] | **partial** → reference/whirlaway.md updated with Brakedown+Binius | dual-algebra: 2 PCS, 1 IOP, 1 hash, 14 languages |

## PCS backends

| proposal | in reference? | target |
|----------|--------------|--------|
| [[brakedown-pcs]] | **yes** → reference/polynomial-commitment.md (primary PCS) | Merkle-free PCS — 1-5 KiB proofs |
| [[binius-pcs]] | no | F₂ tower native PCS — 32-64× cheaper bitwise ops |

## proof size and verification

| proposal | in reference? | target |
|----------|--------------|--------|
| [[algebraic-extraction]] | no (near-term WHIR optimization, Brakedown supersedes) | batch algebraic opening — 157 KiB → 5-12 KiB |
| [[gravity-commitment]] | no | mass-weighted encoding — verification ∝ importance |

## composition and recursion

| proposal | in reference? | target |
|----------|--------------|--------|
| [[folding-first]] | **yes** → reference/recursion.md (HyperNova folding-first) | 70K constraints → 30 field ops |
| [[proof-carrying]] | **yes** → reference/recursion.md (proof-carrying section) | zero proving latency |
| [[universal-accumulator]] | no | fold ALL proof types into one ~200 byte object |

## prover optimization

| proposal | in reference? | target |
|----------|--------------|--------|
| [[tensor-compression]] | no | O(√N) memory, O(N) streaming — mobile devices |
| [[gpu-prover]] | no | full pipeline in VRAM — 45-100× throughput |

## domain-specific

| proposal | in reference? | target |
|----------|--------------|--------|
| [[ring-aware-fhe]] | no | native TFHE bootstrapping — ring-structured CCS + jets |

## lifecycle

| status | meaning |
|--------|---------|
| **in reference** | merged into canonical spec — this is the architecture |
| accepted | approved — ready to implement |
| draft | idea captured, open for discussion |
