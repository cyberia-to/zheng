---
tags: cyber, cip
crystal-type: process
crystal-domain: cyber
status: accepted
date: 2026-03-17
origin: proof-horizons.md horizon 3
diffusion: 0.00010722364868599256
springs: 0.00007019991600688145
heat: 0.00003419142694206788
focus: 0.00008151008453347325
gravity: 0
density: 0
---
# proof-carrying computation

proofs accumulate during nox execution via per-step HyperNova folding. eliminates the separate proving phase entirely. when computation finishes, the proof is already done — run the O(1) decider.

## the construction

```
reduce_with_proof(s, formula, f, acc) →
  let (tag, body) = formula
  let (result, f', trace_row) = dispatch(s, tag, body, f)
  let acc' = fold_row(acc, trace_row)      // one CCS fold per reduce() call
  (result, f', acc')
```

each reduce() call:
1. produces the usual result and focus update
2. generates one trace row
3. incrementally folds that row into a running accumulator

at the end: the accumulator IS the proof (after one decider call).

## cost analysis

```
current:
  compute: N reduce() calls                    → result + trace
  prove:   commit trace O(N log N) + sumcheck  → proof
  total:   ~2N log N operations

proof-carrying:
  compute: N reduce() calls                    → result + accumulator
  fold:    N × ~30 field ops per fold          → accumulator
  decider: 1 × 70K constraints                → proof
  total:   ~N + 30N + 70K = ~31N operations
```

for N = 2²⁰: current = ~20M ops, proof-carrying = ~31M ops. comparable, but proof is ready at computation end — zero additional latency.

## the deep implication

if every nox computation carries its proof:

- **memoization is proof-verified**: `(H(object), H(formula)) → (H(result), acc)` — the cache entry IS a proof
- **network propagation carries proofs**: a neuron computes a cyberlink and gossips it with the proof attached
- **verification is always O(1)**: the receiver runs the decider (70K constraints) regardless of original computation size
- **no proving infrastructure**: no proving queues, no prover-verifier asymmetry. every device is a prover

the cybergraph memo cache becomes a distributed proven knowledge base. every `ask()` that hits cache returns a verified answer at zero compute cost.

## row-by-row folding

HyperNova folds complete CCS instances. row-by-row folding requires access to adjacent rows for transition constraints (AIR constraint: row t relates to row t+1). solution: sliding-window fold of width 2 — fold (row_t, row_{t+1}) as one CCS instance:

```
fold(acc, (row_0, row_1)) → acc₁
fold(acc₁, (row_1, row_2)) → acc₂
fold(acc₂, (row_2, row_3)) → acc₃
...
```

each fold sees the transition constraint between consecutive rows. row_{t} appears in two consecutive folds — once as "current" and once as "previous." the overlap ensures transition constraints are fully checked.

## open questions

1. **sliding-window correctness**: formal proof that width-2 folding captures all AIR transition constraints. multi-row patterns (hash: 300 rows, inv: 64 rows) may need wider windows
2. **accumulator portability**: the accumulator must travel with the result. serialization cost: ~200 bytes (constant regardless of computation size). acceptable for network propagation
3. **non-deterministic hints**: pattern 16 (hint) introduces prover-supplied witnesses. folding through hints requires careful handling — the accumulator must commit to the hint values without revealing them

see [[zheng-2]] for integrated architecture, [[folding-first]] for block-level composition