---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: recursive composition spec, proof recursion, IVC spec
diffusion: 0.00010722364868599256
springs: 0.002236585268266477
heat: 0.0015539445110052553
focus: 0.0010353763070239772
gravity: 0
density: 0.64
---
# recursion

the recursive composition protocol for [[zheng]]. [[HyperNova]] folding over [[CCS]] is the primary composition mechanism at every level: transaction, block, epoch. per-step folding cost: ~30 field ops + 1 [[hemera]] hash. the decider runs ONCE at the end. with recursive [[Brakedown]], the decider verifier is ~8,000 constraints (down from ~70,000 with WHIR).

tree aggregation and DAG merging remain available for specific topologies. proof-carrying computation folds during [[nox]] execution itself.

## folding-first composition (primary)

```
fold(accumulator, instance) → accumulator'
  cost: ~30 field operations + 1 hemera hash

decide(accumulator) → proof
  cost: ~8,000 constraints (Brakedown) / ~70,000 constraints (WHIR legacy)
```

for N independent proofs:

```
1000 transactions in a block:
  fold: 1000 steps × ~30 field ops = 30K field operations (trivial)
  decider: 1 × ~8K constraints (Brakedown)
  total: ~8K constraints + 30K field ops

vs tree aggregation (legacy):
  10 levels × 2 verifications × 70K constraints = 1.4M constraints

reduction: ~100×
```

## epoch composition

```
folding-first:
  block 1 → fold → block 2 → fold → ... → block 1000 → fold → decider
  1000 folds × 30 field ops = 30K field ops
  1 decider = ~8K constraints (Brakedown)
  total: ~8K constraints + negligible folding cost

vs full recursion (legacy):
  1000 blocks/epoch × 70K constraints/recursive verify = 70M constraints

reduction: ~5,800×
```

## proof-carrying computation

proofs accumulate during nox execution via per-step HyperNova folding. eliminates the separate proving phase entirely. when computation finishes, the proof is already done — run the O(1) decider.

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

### cost analysis

```
proof-carrying:
  compute: N reduce() calls                    → result + accumulator
  fold:    N × ~30 field ops per fold          → accumulator
  decider: 1 × ~8K constraints (Brakedown)   → proof
  total:   ~N + 30N + 12K = ~31N operations

vs separate proving (legacy):
  compute: N reduce() calls                    → result + trace
  prove:   commit trace O(N log N) + sumcheck  → proof
  total:   ~2N log N operations
```

for N = 2^20: proof-carrying = ~31M ops, separate = ~20M ops. comparable, but proof is ready at computation end — zero additional latency.

### implications

- **memoization is proof-verified**: `(H(object), H(formula)) → (H(result), acc)` — the cache entry IS a proof
- **network propagation carries proofs**: a neuron computes a cyberlink and gossips it with the proof attached
- **verification is always O(1)**: the receiver runs the decider (~8K constraints) regardless of original computation size
- **no proving infrastructure**: no proving queues, no prover-verifier asymmetry. every device is a prover

## cross-algebra folding

with algebra-polymorphic nox, different transactions may execute in different algebras (F_p, F₂, F_{p³}). universal CCS with selectors enables heterogeneous folding:

```
universal_ccs = {
  sel_Fp:   1 for Goldilocks rows, 0 otherwise
  sel_F2:   1 for binary rows, 0 otherwise
  sel_ring: 1 for ring-structured rows (Wav/FHE), 0 otherwise
}

fold(acc, goldilocks_instance)  → acc'    (~30 F_p ops + 1 hemera)
fold(acc', binary_instance)     → acc''   (~30 F_p ops + 1 hemera)
fold(acc'', ring_instance)      → acc'''  (~30 F_p ops + 1 hemera)

one accumulator, all algebras
decider: one proof, ~5 μs verification (Brakedown)
```

boundary cost per cross-algebra fold: ~766 F_p constraints (30 field ops + 1 hemera hash). negligible vs execution cost.

## legacy: recursion mechanics (WHIR)

```
Level 0: prove computation C       → proof π₀   (constraint count = |C|)
Level 1: prove verify(π₀)          → proof π₁   (~70K constraints with WHIR, ~8K with Brakedown)
Level 2: prove verify(π₁)          → proof π₂   (same)
  ...
Level k: proof π_k                              (constant size)
```

invariants (Brakedown):
- constraint count per recursion level: ~8,000 (with jets)
- proof size: constant across levels (~2 KiB at 128-bit)
- verification time: constant (~5 μs)

invariants (WHIR legacy):
- constraint count per recursion level: ~70,000 (with jets), ~600,000 (without)
- proof size: constant across levels (~60-157 KiB depending on security parameter)
- verification time: constant (~290 μs at 100-bit, ~1.0 ms at 128-bit)

## tree aggregation (secondary)

tree aggregation is available for parallel proving topologies but is no longer the primary composition mechanism. folding-first is preferred.

for N independent proofs (block transactions):

```
level 0:  π₁  π₂  π₃  π₄  ...  π_N        N leaf proofs
level 1:   π₁₂    π₃₄    ...              ⌈N/2⌉ pair verifications
level 2:     π₁₋₄      ...                ⌈N/4⌉
  ...
level log₂(N):  π_block                    1 block proof
```

| metric | value |
|---|---|
| depth | ⌈log₂(N)⌉ |
| total prover work | O(N) verifications |
| latency | O(log N) sequential steps |
| parallelism | full within each level |
| output | 1 proof, O(1) verification |

pair verification at each node: prove(verify(π_left) AND verify(π_right)). constraint count per pair: ~24,000 (Brakedown) / ~140,000 (WHIR legacy).

## folding cost summary

[[HyperNova]] folding over [[CCS]]:

| metric | folding (Brakedown) | folding (WHIR legacy) | full recursion (legacy) |
|---|---|---|---|
| cost per step | ~30 field ops + 1 hash | ~30 field ops + 1 hash | ~70K constraints |
| decider cost | ~8K constraints | ~70K constraints | N/A |
| total for N=1000 | 30K ops + 8K constraints | 30K ops + 70K constraints | 70M constraints |

### accumulator format

```
accumulator = {
  committed_instance: CCSInstance,    // folded CCS instance
  witness_commitment: [u8; 64],       // hemera digest of folded witness
  error_term: GoldilocksElement,      // accumulated folding error
  step_count: u64,                    // number of folds applied
}
```

the accumulator grows by a constant amount per fold. the decider proof at the end verifies the entire accumulated sequence.

## folding algorithm

the [[HyperNova]] folding protocol over [[CCS]]:

### fold(accumulator, instance, witness)

given running accumulator A = (E_acc, u_acc, w_acc, e_acc) and new CCS instance (E_new, u_new, w_new):

1. compute cross-term T = cross_term(A, new_instance) — field operations over CCS matrices
2. derive challenge β from transcript: absorb A.commitment, new.commitment, T; squeeze β
3. fold instances: E_folded = E_acc + β × E_new
4. fold witnesses: w_folded = w_acc + β × w_new
5. fold error: e_folded = e_acc + β × T + β² × e_new
6. update commitment: C_folded = hemera(w_folded)
7. return new accumulator

### decide(accumulator, params)

prove that the accumulated CCS instance is satisfiable. this is a standard [[SuperSpartan]] + [[Brakedown]] proof of the folded instance. cost: ~8,000 constraints (Brakedown) / ~70,000 constraints (WHIR legacy).

### cross-term computation

for CCS with matrices M_1,...,M_t and sets S_1,...,S_q:

```
T = Σ_j c_j × Σ over all mixed products of (M_i · z_acc) and (M_i · z_new) from set S_j
```

cost: O(|S| × nnz) where nnz is total non-zeros across matrices.

### soundness

folding preserves CCS satisfiability. if either the accumulator or the new instance is unsatisfying, the error term e_folded will be non-zero with overwhelming probability over the choice of β.

### CCS compatibility

[[HyperNova]] folds over [[CCS]] instances. since [[SuperSpartan]] already uses CCS, the folding scheme and the proof system share the same constraint language:

- fold a [[cyberlink]] insertion proof → CCS instance
- fold a rank update → CCS instance
- fold a cross-shard merge → CCS instance

one framework, one accumulator type, any proof in the zheng taxonomy.

## DAG merging

for proofs with dependency structure (cross-shard, multi-validator):

```
PCD_merge(π_A, π_B) → π_AB
  where π_A and π_B may depend on shared state
```

applicable to:
- cross-shard [[cybergraph]] queries spanning multiple shards
- multi-validator block proving (different validators prove different transaction subsets)
- delivery proof chains (each relay proves its hop independently)

DAG merging is a generalization of tree aggregation where the merge topology matches the data dependency graph rather than a balanced binary tree.

## row-by-row folding

HyperNova folds complete CCS instances. row-by-row folding requires access to adjacent rows for transition constraints (AIR constraint: row t relates to row t+1). solution: sliding-window fold of width 2 — fold (row_t, row_{t+1}) as one CCS instance:

```
fold(acc, (row_0, row_1)) → acc₁
fold(acc₁, (row_1, row_2)) → acc₂
fold(acc₂, (row_2, row_3)) → acc₃
...
```

each fold sees the transition constraint between consecutive rows. row_{t} appears in two consecutive folds — once as "current" and once as "previous." the overlap ensures transition constraints are fully checked.

## depth bounds

| scenario | depth | total prover cost (Brakedown) |
|---|---|---|
| single transaction | 0 | |C| constraints |
| block (1000 txns, fold) | 1 | 1000 × 30 ops + 8K decider |
| block (1000 txns, tree) | ~10 | O(1000) × 8K + 10 × 16K |
| epoch (1000 blocks, fold) | 1 | 1000 × 30 ops + 8K decider |
| epoch + block combined | 2 | block fold + epoch fold + 2 deciders |
| cross-epoch query | 1 | one recursive verification of epoch proof |

practical depth limit: unbounded in theory. with folding, each step adds ~30 field ops. the decider runs once at ~8K constraints. for latency-sensitive applications, folding is always preferred over tree aggregation.

## security of recursive composition

recursive soundness inherits from the base proof system. if the base zheng proof has soundness error ε per verification, k levels of recursion have error ≤ k × ε. at 128-bit security: ε ≈ 2^{-128}, so even 1000 recursion levels give error ≤ 1000 × 2^{-128} ≈ 2^{-118} — negligible.

the critical requirement: the [[verifier]] must be faithfully encoded as [[nox]] patterns. any discrepancy between the nox verifier program and the mathematical verifier specification would break recursive soundness.

## open questions

1. **sliding-window correctness**: formal proof that width-2 folding captures all AIR transition constraints. multi-row patterns (hash: 300 rows, inv: 64 rows) may need wider windows
2. **universal CCS overhead**: padding smaller instances to match universal CCS dimensions wastes constraints. CycleFold addresses this but adds protocol complexity
3. **cross-algebra soundness**: does folding F_p and F₂ instances into the same accumulator preserve HyperNova security guarantees?
4. **accumulator portability**: the accumulator must travel with the result. serialization cost: ~200 bytes (constant regardless of computation size). acceptable for network propagation

see [[verifier]] for the standalone verification algorithm, [[constraints]] for the AIR format, [[transcript]] for Fiat-Shamir in recursive proofs, [[sumcheck]] for the core protocol, [[Brakedown]] for the PCS, [[WHIR]] for the legacy PCS