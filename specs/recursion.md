---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: recursive composition spec, proof recursion, IVC spec
---
# recursion

> superseded: this page described the legacy fold (feature `legacy`, unsound, removed in phase 5) as zheng's composition protocol; long computations are now accumulated (`accumulation.md`, `machine.md`, phase 3) and recursion proper is composition only.

## two different things

- accumulation — how a long computation gets a proof whose size and verification are constant in the number of steps. phase 3 (`accumulation.md`, `machine.md`, landing in this release): the nox machine is one uniform step relation; each step's Reed–Solomon evaluation claims are accumulated hash-based, ARC/WARP-style (ARC eprint 2024/1731, WARP 2025/753) — batch the claims with a sumcheck, commit one combined word, sample out-of-domain points, open a few query positions. the accumulator is one root plus a fixed number of claims; the decider is ONE WHIR opening (envelope profile 4). goal: ≤ 64 KB, verify ≤ 1 ms, constant in steps; measured TODO(F-numbers).
- recursion proper — proving a statement about proofs: a zheng verifier written as a nox program (the Trident verifier) and proven like any other program. it composes proofs (aggregate, attest that a set of proofs verified, cross a trust boundary). it is never the mechanism for size.

## composition through a verifier program

```
proof_A = prove(computation)
proof_B = prove(verify_program(statement_A, proof_A))
```

the cost of `proof_B` is the cost of proving the verifier program: the WHIR opening's hemera Merkle paths and the Spartan verifier's field arithmetic. it is a proof of an ordinary nox execution and goes through the same profiles (succinct, zk, or accumulated). measured cost of a verifier-in-nox proof: TODO(F-numbers).

soundness: a composed proof is sound if the inner proof system is and the verifier program faithfully implements the verifier specified in [[execution]] — any discrepancy between the nox verifier and the specified one breaks it. the bits of each layer come from the [[soundness]] ledger; nothing beyond a union bound over the layers is claimed here.

## the legacy fold (historical)

the 0.3/0.4 API folded every CCS instance into one running accumulator `A = (E, u, w, e)` with a homomorphic-style relaxed fold — cross-term `T`, challenge `β` from the transcript, `w' = w_acc + β·w_new`, `e' = e_acc + β·T + β²·e_new` — and recommitted `C' = hemera(w')`. a hash commitment is not homomorphic, so the verifier could never check that `C'` commits the folded witness, nor that `e'` was formed from `T`: the fold was unchecked, the statement unbound and the constant wire free ([[decider]] §soundness). a width-2 sliding window (fold `(row_t, row_{t+1})`) carried transition constraints, and a selector "universal CCS" padded heterogeneous instances to one shape. its per-fold and per-decider cost figures were never measured on a sound construction and are withdrawn. the code stays behind the `legacy` feature for one release.

## open questions

1. machine relation width: which step relation (`machine.md`) keeps the per-step accumulation cost low while covering every nox pattern, including the multi-row hash.
2. cross-algebra: whether F₂ or ring instances join the same accumulator (one RS code over Goldilocks today) or are proven separately and composed.
3. the Trident verifier: verifier-in-nox cost, and which profile proves it.

see [[verifier]] for the shipped verifiers, [[transcript]] for Fiat–Shamir, [[sumcheck]] for the core protocol, [[lens]] for polynomial commitment.
