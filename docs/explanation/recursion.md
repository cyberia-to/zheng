# accumulation and recursive composition

two words that zheng's older pages used as one:

- accumulation — folding *claims* without verifying *proofs*. an accumulator carries one Merkle root and a fixed number of evaluation claims from step to step; no verifier circuit is ever built. this is how [[zheng]] proves an unbounded computation at a size independent of its length. it is the default.
- recursion — a proof that verifies a proof: [[IVC]] and [[PCD]] proper, with the zheng verifier written as a [[nox]] program. in a hash-only world it does not shrink the final proof — the outer proof carries its own Merkle paths again — so it is a tool for composition, never for size.

this split is settled in the [[soft3/proposals/proof-system-repair|proof-system repair]] (§4). the earlier design — homomorphic folding of committed CCS instances over hemera, with "the accumulator is the proof" and a small fixed decider — never worked: folding by homomorphism needs a homomorphic commitment, and [[hemera]] is a hash. the fold was never checked, and that code stays only behind cargo feature `legacy` (unsound, off by default) until phase 5 deletes it.

## accumulation (phase 3, in progress)

the nox machine becomes one uniform step relation: one [[CCS]] for one nox reduction step, with continuity and memory arguments between steps (`specs/machine.md`, landing with phase 3). proving a long computation is accumulating its steps:

```
for each step i:
    claims_i  = evaluation claims of step i's relation (Reed–Solomon codewords)
    batch claims_i with the running accumulator by a sumcheck
    commit one combined word (hemera Merkle root)
    sample out-of-domain points, open a few query positions
    acc_i = (root, fixed number of claims)        size independent of i

decider: one WHIR opening of the final accumulator
```

this is hash-based accumulation of Reed–Solomon evaluation claims in the style of ARC (eprint 2024/1731) and WARP (eprint 2025/753): sound up to the list-decoding regime, resting on the random-oracle model only. the accumulator never grows; the decider proof is one opening.

figures: decider proof ≤ 64 KB goal, decider 44–93 KB measured (one WHIR opening of an Fp3 word, ℓ = 14…21; `audit/accumulation-2026-10.md`); verification ≤ 1 ms goal, decider verify 3.1–4.6 ms measured (hash.tri, merkle-32; whole machine proof 5–40 ms, linear in segments). accumulation alone does not make the proof constant: every step's openings travel until recursion is built. the goal of the repair is any nox computation → a proof ≤ 64 KB, post-quantum, verified in ≤ 1 ms, constant in the number of steps.

## what accumulation serves

| need | shape |
|---|---|
| a long nox computation | accumulate every step, decide once |
| [[fold mining]]: a cluster of tickets becomes one decider before minting | each ticket's claims and the cluster tree are accumulation steps; the root is one decider |
| a [[light client]] accepts a checkpoint over many epochs | accumulate per epoch, decide at the checkpoint; the checkpoint is the state root plus the decider proof of the accumulator (≤ 64 KB goal, decider 44–93 KB measured (one WHIR opening of an Fp3 word, ℓ = 14…21; `audit/accumulation-2026-10.md`)) |
| a block of many transactions | the transactions' claims accumulate into one accumulator, one decider |

none of these needs a proof of a proof.

## recursion proper (composition only)

the zheng verifier performs [[Goldilocks]] and Fp3 arithmetic, calls [[hemera]] and evaluates multilinear polynomials — all native to nox. so it can be written as a nox program (the second verifier, in Trident, agreeing with the Rust verifier on every fixture), and `verify(π)` can itself be proven.

where the stack uses it:

- composition across domains, or across a version boundary (an old proof inside a new one).
- closing the self-hosting loop: the proof that nox proves nox is an accumulation over the self-hosting trace, with at most one recursion step at the end.
- the fallback if ARC's prover is too slow or its argument does not close on review: bounded-depth recursion through the Trident verifier, one level at a time — costlier, standard, sound.

a recursion step is expensive: the verifier's Merkle paths and hemera calls become a large relation, and the outer proof carries Merkle paths of its own. it is affordable once, never per step. its measured cost does not exist yet.

## why the old picture was wrong

- folding a committed instance with a random linear combination needs the commitment to be linear in the committed data. a Merkle root of a codeword is not; the folded commitment could not be checked, and the error vector was prover-chosen.
- "the proof does not grow" was true of the accumulator's bytes and false of its soundness: an unchecked fold accepts anything.
- a recursive verifier was never built, so the per-level constraint counts and depth-soundness figures the old pages quoted described nothing.

see [[zheng/specs/soundness|the soundness ledger]] for the bits of every shipped component, [[zheng/docs/explanation/CCS|CCS]] for the constraint language both the step relation and the profiles use.
