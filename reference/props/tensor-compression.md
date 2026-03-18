---
tags: cyber, cip
crystal-type: process
crystal-domain: cyber
status: accepted
date: 2026-03-17
origin: proof-horizons.md horizon 5
---
# tensor trace compression

exploit low tensor rank of structured nox traces. prover memory: O(N) → O(√N). prover time: O(N log N) → O(N) streaming. mobile devices become first-class provers.

## the observation

nox traces have structure the prover currently ignores:

1. **pattern repetition**: same pattern type in consecutive rows (64 rows of inv, 300 rows of hash). constraint selectors are locally constant
2. **tree locality**: axis traversals follow tree paths. parent-child relationships span adjacent rows
3. **column sparsity**: most patterns use 3-4 of 16 registers. unused registers are zero or carry-forward
4. **memoization hits**: repeated sub-computations produce identical trace fragments

## tensor decomposition

if the trace matrix T has rank r << min(N, 16):

```
T ≈ Σᵢ₌₁ʳ aᵢ ⊗ bᵢ

where aᵢ ∈ F^N (row vectors), bᵢ ∈ F^16 (column vectors)
```

for r = 32 (typical: 16 pattern types × 2 for transitions):
- commit to 32 × (N + 16) ≈ 32N elements instead of 16N
- slight commitment overhead but massive opening reduction
- each opening = r inner products in streaming pass

## streaming sumcheck

```
standard sumcheck:
  round i: evaluate Σ_{remaining vars} C(f, ...)
  cost per round: O(2^{k-i}) where k = n + m
  total: O(N × 16)
  memory: O(N × 16) — must hold full trace

streaming sumcheck with tensor:
  round i: evaluate Σ C(Σ aᵢ ⊗ bᵢ, ...)
  cost per round: O(r × 2^{n-i})
  total: O(r × N)
  memory: O(r × √N) with checkpointing
```

for r = 32, N = 2²⁰:
- standard: 16M ops, 16 MB memory
- tensor: 32M ops (2× more but streaming), ~32 KB memory (1000× less)

## hemera-native commitment of tensor factors

```
standard:     C = hemera_merkle(evaluations)           O(N log N) hashes
tensor:       C_a = [hemera(a₁), ..., hemera(aᵣ)]    r × O(N) hashes
              C_b = [hemera(b₁), ..., hemera(bᵣ)]    r × O(16) hashes
              C = hemera(C_a, C_b)                    1 hash

total: r × N ≈ 32N hashes (vs N log N for standard WHIR)
for N = 2²⁰: 32M vs 20M hashes — comparable, but streaming
```

## mobile proving

with O(√N) memory, a phone with 4 GB RAM can prove:
- N = 2³⁰ traces (1B steps): needs ~32 × √(2³⁰) ≈ 1 MB
- versus standard: 16 GB (impossible on phone)

combined with proof-carrying ([[proof-carrying]]): the phone folds each step incrementally. never materializes the full trace. proves arbitrary computations in bounded memory.

## open questions

1. **empirical tensor rank**: what is r for real nox workloads? cyberlink insertion (many hemera hashes → pattern 15 dominates → low rank?), recursive verification (mixed patterns → higher rank?), tri-kernel SpMV (regular structure → low rank?)
2. **rank bound guarantee**: is r ≤ 32 provable for nox traces, or only empirically observed? a theoretical bound would strengthen the proposal
3. **checkpointing strategy**: √N checkpoints at equal intervals, or adaptive placement at pattern boundaries? pattern-aware checkpointing may reduce re-execution cost

see [[zheng-2]] for integrated architecture, [[proof-carrying]] for streaming integration
