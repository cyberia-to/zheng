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

the recursive composition protocol for [[zheng]]. [[HyperNova]] folding over [[CCS]]. per-step folding cost: ~30 field ops + 1 [[hemera]] hash. the decider runs once at the end. decider cost: ~825 constraints (CCS jet + batch + algebraic FS).

## folding

```
fold(accumulator, instance) -> accumulator'
  cost: ~30 field operations + 1 hemera hash

decide(accumulator) -> proof
  cost: ~825 constraints (CCS jet + batch + algebraic FS)
```

for N independent proofs:

```
1000 transactions in a block:
  fold: 1000 steps * ~30 field ops = 30K field operations (trivial)
  decider: 1 * ~825 constraints
  total: ~825 constraints + 30K field ops
```

## epoch composition

```
block 1 -> fold -> block 2 -> fold -> ... -> block 1000 -> fold -> decider
1000 folds * 30 field ops = 30K field ops
1 decider = ~825 constraints
total: ~825 constraints + negligible folding cost
```

## proof-carrying computation

proofs accumulate during nox execution via per-step HyperNova folding. eliminates the separate proving phase entirely. when computation finishes, the proof is already done — run the O(1) decider.

```
reduce_with_proof(s, formula, f, acc) ->
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

### cost

```
proof-carrying:
  compute: N reduce() calls                    -> result + accumulator
  fold:    N * ~30 field ops per fold          -> accumulator
  decider: 1 * ~825 constraints               -> proof
  total:   ~31N operations
```

### implications

- **memoization is proof-verified**: `(H(object), H(formula)) -> (H(result), acc)` — the cache entry IS a proof
- **network propagation carries proofs**: a neuron computes a cyberlink and gossips it with the proof attached
- **verification is always O(1)**: the receiver runs the decider (~825 constraints) regardless of original computation size
- **no proving infrastructure**: no proving queues, no prover-verifier asymmetry. every device is a prover

## cross-algebra folding

with algebra-polymorphic nox, different transactions may execute in different algebras (F_p, F_2, F_{p^3}). universal CCS with selectors enables heterogeneous folding:

```
universal_ccs = {
  sel_Fp:   1 for Goldilocks rows, 0 otherwise
  sel_F2:   1 for binary rows, 0 otherwise
  sel_ring: 1 for ring-structured rows (Wav/FHE), 0 otherwise
}

fold(acc, goldilocks_instance)  -> acc'    (~30 F_p ops + 1 hemera)
fold(acc', binary_instance)     -> acc''   (~30 F_p ops + 1 hemera)
fold(acc'', ring_instance)      -> acc'''  (~30 F_p ops + 1 hemera)

one accumulator, all algebras
decider: one proof, ~5 us verification
```

boundary cost per cross-algebra fold: ~766 F_p constraints (30 field ops + 1 hemera hash). negligible vs execution cost.

## folding algorithm

the [[HyperNova]] folding protocol over [[CCS]]:

### fold(accumulator, instance, witness)

given running accumulator A = (E_acc, u_acc, w_acc, e_acc) and new CCS instance (E_new, u_new, w_new):

1. compute cross-term T = cross_term(A, new_instance) — field operations over CCS matrices
2. derive challenge beta from transcript: absorb A.commitment, new.commitment, T; squeeze beta
3. fold instances: E_folded = E_acc + beta * E_new
4. fold witnesses: w_folded = w_acc + beta * w_new
5. fold error: e_folded = e_acc + beta * T + beta^2 * e_new
6. update commitment: C_folded = hemera(w_folded)
7. return new accumulator

### decide(accumulator, params)

prove that the accumulated CCS instance is satisfiable. a standard [[SuperSpartan]] + [[Brakedown]] proof of the folded instance. cost: ~825 constraints.

### cross-term computation

for CCS with matrices M_1,...,M_t and sets S_1,...,S_q:

```
T = sum_j c_j * sum over all mixed products of (M_i * z_acc) and (M_i * z_new) from set S_j
```

cost: O(|S| * nnz) where nnz is total non-zeros across matrices.

### soundness

folding preserves CCS satisfiability. if either the accumulator or the new instance is unsatisfying, the error term e_folded will be non-zero with overwhelming probability over the choice of beta.

### CCS compatibility

[[HyperNova]] folds over [[CCS]] instances. since [[SuperSpartan]] already uses CCS, the folding scheme and the proof system share the same constraint language:

- fold a [[cyberlink]] insertion proof -> CCS instance
- fold a rank update -> CCS instance
- fold a cross-shard merge -> CCS instance

one framework, one accumulator type, any proof in the zheng taxonomy.

## row-by-row folding

HyperNova folds complete CCS instances. row-by-row folding requires access to adjacent rows for transition constraints (AIR constraint: row t relates to row t+1). solution: sliding-window fold of width 2 — fold (row_t, row_{t+1}) as one CCS instance:

```
fold(acc, (row_0, row_1)) -> acc_1
fold(acc_1, (row_1, row_2)) -> acc_2
fold(acc_2, (row_2, row_3)) -> acc_3
...
```

each fold sees the transition constraint between consecutive rows. row_t appears in two consecutive folds — once as "current" and once as "previous." the overlap ensures transition constraints are fully checked.

## accumulator format

```
accumulator = {
  committed_instance: CCSInstance,    // folded CCS instance
  witness_commitment: [u8; 64],       // hemera digest of folded witness
  error_term: GoldilocksElement,      // accumulated folding error
  step_count: u64,                    // number of folds applied
}
```

the accumulator grows by a constant amount per fold. the decider proof at the end verifies the entire accumulated sequence. serialization cost: ~200 bytes (constant regardless of computation size).

## depth bounds

| scenario | depth | total prover cost |
|---|---|---|
| single transaction | 0 | |C| constraints |
| block (1000 txns, fold) | 1 | 1000 * 30 ops + 825 decider |
| epoch (1000 blocks, fold) | 1 | 1000 * 30 ops + 825 decider |
| epoch + block combined | 2 | block fold + epoch fold + 2 deciders |
| cross-epoch query | 1 | one recursive verification of epoch proof |

folding depth is unbounded in theory. each step adds ~30 field ops. the decider runs once at ~825 constraints. folding is always preferred for composition.

## security of recursive composition

recursive soundness inherits from the base proof system. if the base zheng proof has soundness error epsilon per verification, k levels of recursion have error <= k * epsilon. at 128-bit security: epsilon ~ 2^{-128}, so even 1000 recursion levels give error <= 1000 * 2^{-128} ~ 2^{-118} — negligible.

the critical requirement: the [[verifier]] must be faithfully encoded as [[nox]] patterns. any discrepancy between the nox verifier program and the mathematical verifier specification would break recursive soundness.

## open questions

1. **sliding-window correctness**: formal proof that width-2 folding captures all AIR transition constraints. multi-row patterns (hash: 300 rows, inv: 64 rows) may need wider windows
2. **universal CCS overhead**: padding smaller instances to match universal CCS dimensions wastes constraints. CycleFold addresses this but adds protocol complexity
3. **cross-algebra soundness**: does folding F_p and F_2 instances into the same accumulator preserve HyperNova security guarantees?

see [[verifier]] for the standalone verification algorithm, [[constraints]] for the AIR format, [[transcript]] for Fiat-Shamir in recursive proofs, [[sumcheck]] for the core protocol, [[lens]] for polynomial commitment
