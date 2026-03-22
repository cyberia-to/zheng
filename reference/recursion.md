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

the recursive composition protocol for [[zheng]]. defines how proofs compose via tree aggregation, sequential folding ([[HyperNova]] over [[CCS]]), and DAG merging. specifies depth bounds, cost invariants, and the accumulator format.

## recursion mechanics

```
Level 0: prove computation C       → proof π₀   (constraint count = |C|)
Level 1: prove verify(π₀)          → proof π₁   (~70K constraints, ~70 ms)
Level 2: prove verify(π₁)          → proof π₂   (~70K constraints, ~70 ms)
  ...
Level k: proof π_k                              (~60-157 KiB, same as π₀)
```

invariants:
- constraint count per recursion level: ~70,000 (with jets), ~600,000 (without)
- proof size: constant across levels (~60-157 KiB depending on security parameter)
- verification time: constant (~290 μs at 100-bit, ~1.0 ms at 128-bit)

## tree aggregation

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

pair verification at each node: prove(verify(π_left) AND verify(π_right)). constraint count per pair: ~140,000 (two verifications with jets).

## sequential folding

for proofs arriving in sequence (epoch blocks), [[HyperNova]] folding over [[CCS]] avoids full verification at each step:

```
fold(accumulator, instance) → accumulator'
  cost: O(1) field operations + one hemera hash

decider(accumulator) → stark proof
  cost: ~70,000 constraints (one verification)
```

| metric | full recursion | folding |
|---|---|---|
| cost per step | ~70,000 constraints | ~O(1) field ops + 1 hash |
| total for N steps | N × 70,000 | N × O(1) + 70,000 |
| savings for N=1000 | — | 69,930,000 constraints eliminated |

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

prove that the accumulated CCS instance is satisfiable. this is a standard [[SuperSpartan]] + [[WHIR]] proof of the folded instance. cost: ~70,000 constraints (one verification worth).

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

## depth bounds

| scenario | depth | total prover cost |
|---|---|---|
| single transaction | 0 | |C| constraints |
| block (1000 txns, tree) | ~10 | O(1000) × 70K + 10 × 140K |
| epoch (1000 blocks, fold) | 1 | 1000 × O(1) + 70K |
| epoch + block combined | ~11 | block tree + epoch fold + decider |
| cross-epoch query | 1 | one recursive verification of epoch proof |

practical depth limit: unbounded in theory. in practice, each level adds ~70K constraints of prover work. for latency-sensitive applications, 10-15 levels suffice (covers blocks of millions of transactions via tree aggregation).

## security of recursive composition

recursive soundness inherits from the base proof system. if the base zheng proof has soundness error ε per verification, k levels of recursion have error ≤ k × ε. at 128-bit security: ε ≈ 2^{-128}, so even 1000 recursion levels give error ≤ 1000 × 2^{-128} ≈ 2^{-118} — negligible.

the critical requirement: the [[verifier]] must be faithfully encoded as [[nox]] patterns. any discrepancy between the nox verifier program and the mathematical verifier specification would break recursive soundness.

see [[verifier]] for the standalone verification algorithm, [[constraints]] for the AIR format, [[transcript]] for Fiat-Shamir in recursive proofs, [[sumcheck]] for the core protocol, [[WHIR]] for the PCS