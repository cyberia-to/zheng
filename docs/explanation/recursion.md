# recursive proof composition

the most powerful property of [[zheng]] is that its verifier is a [[nox]]
program. a nox program can be proved by zheng. therefore: prove the act
of verification, and the result is a new proof — one that attests to the
correctness of another proof. this is recursion. it is the mechanism that
makes everything scale.

## the core idea

a [[nox]] execution trace records every step of a computation. zheng
takes that trace and produces a proof that the computation was performed
correctly. the verifier checks the proof in sub-millisecond time.

now: the verifier itself is a computation. it performs [[Goldilocks]]
field arithmetic, calls [[hemera]] for Fiat-Shamir challenges, evaluates
low-degree polynomials. all of these are native nox operations. so the
verifier can be written as a nox program, executed, traced, and proved
by zheng.

```
proof_A = zheng.prove(computation)
proof_B = zheng.prove(zheng.verify(proof_A))
```

proof_B attests that proof_A was valid. anyone who checks proof_B knows
that the original computation was correct, without ever seeing proof_A
or the original trace. the recursion can continue: prove the verification
of proof_B to get proof_C, and so on, to arbitrary depth.

each recursion level costs approximately 70,000 constraints when [[nox]]
uses jets (hardware-accelerated primitives for hemera hashing and field
operations). without jets, the cost rises to roughly 600,000 constraints.
the constraint count is fixed regardless of what the original computation
was — a trivial identity proof and a massive neural network inference
both compress to the same verification cost at the next recursion level.

## why recursion matters

without recursion, verification cost grows linearly with the number of
computations. a block containing 1000 transactions requires 1000 separate
proof verifications. a light client syncing 10,000 blocks needs 10,000
verification passes. the work scales with the data, which defeats the
purpose of succinct proofs.

with recursion, 1000 transaction proofs aggregate into one proof. verify
that one proof, and you know all 1000 transactions were valid. a light
client receives a single epoch proof covering thousands of blocks and
verifies it in under a millisecond. the verification cost becomes O(1)
regardless of how much computation the proof covers.

## three aggregation patterns

different workloads call for different recursion topologies.

### tree aggregation

block proofs use binary tree aggregation. given N transaction proofs,
pair them: verify proof_1 and proof_2 together, producing a combined
proof. verify proof_3 and proof_4, producing another. pair the results.
continue until one proof remains.

```
level 0:  p₁  p₂  p₃  p₄  p₅  p₆  p₇  p₈
level 1:   p₁₂    p₃₄    p₅₆    p₇₈
level 2:     p₁₂₃₄        p₅₆₇₈
level 3:         p₁₂₃₄₅₆₇₈
```

the tree has O(log N) depth. each level performs N/2 pair-verifications
in parallel. the total work is O(N) verifications, but the latency is
O(log N) — and every level can be parallelized across multiple provers.

### sequential folding

epoch proofs aggregate blocks that arrive in sequence. tree aggregation
works here too, but folding is more efficient for sequential data.

folding defers verification. instead of fully verifying each proof at
every step, a folding scheme like [[HyperNova]] absorbs each new proof
with one field operation and one hash. the accumulated "folded instance"
grows by a constant amount per step. at the end of the epoch, one
expensive decider proof verifies the entire folded sequence.

for N blocks in an epoch, full recursion costs N × 70,000 constraints.
folding costs N × (one field op + one hash) plus one final decider of
~70,000 constraints. the savings compound: for an epoch of 1000 blocks,
folding avoids roughly 999 × 70,000 = 69,930,000 constraints.

### DAG merging

cross-shard proofs form directed acyclic graphs. different validators
produce proofs for different shards. these proofs may depend on each
other — a transaction on shard A may reference state proved by shard B.
DAG merging verifies the dependency graph by recursively proving the
verification of proofs from multiple sources, respecting the partial
order of dependencies.

## folding over CCS

[[HyperNova]] implements folding over [[CCS]] (customizable constraint
systems). this is a natural fit for zheng because [[SuperSpartan]]
already uses CCS as its constraint representation. a single constraint
language serves both the proof system and the folding scheme — there is
no translation layer between them.

CCS generalizes R1CS, PLONKish arithmetization, and AIR constraints into
one framework. folding over CCS means zheng can fold any constraint type
that SuperSpartan can prove. the generality is free: it comes from the
algebraic structure of CCS rather than from additional protocol
complexity.

## what recursion enables

O(1) block verification. a validator produces a block proof by
tree-aggregating all transaction proofs. other validators check the
block by verifying one proof instead of re-executing every transaction.

light client sync via epoch proofs. a light client connecting to the
network receives a single proof covering the entire current epoch. one
sub-millisecond verification replaces downloading and checking thousands
of block headers.

off-chain computation with on-chain integrity. any computation that can
run in [[nox]] can be proved by zheng and verified on-chain. the chain
stores the proof, not the computation. machine learning inference, data
processing, complex business logic — all happen off-chain, all
verifiable on-chain.

delivery proof chains. in the [[cyber]] network, messages traverse
multiple hops between nodes. each hop produces a proof of correct
forwarding. the chain of hop proofs folds into a single delivery proof
that attests the message traveled the entire path faithfully. each hop
adds roughly 60,000 constraints; folding reduces the marginal cost per
hop to one field operation and one hash.

neural network inference verification. a model runs in nox, producing
an execution trace. zheng proves the trace. the proof attests that a
specific model with specific weights produced a specific output for a
specific input. recursive composition allows batching: prove 100
[[inferences]], aggregate into one proof, verify once.

## the recursive horizon

the compression is absolute. take any computation expressible in nox —
unbounded in size, unbounded in complexity. prove it. the proof is
~157 KiB. verify the proof. the verification is a fixed-size
computation: ~70,000 constraints, ~70 ms proving time, sub-millisecond
verification. compose, aggregate, fold. the final proof is still
~157 KiB. the final verification is still sub-millisecond.

compute anything. prove it. compress it. verify it once. this is what
recursion gives [[zheng]], and what zheng gives [[cyber]].
