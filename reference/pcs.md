---
tags: cyber, computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: polynomial commitments, polynomial commitment scheme, PCS
---
# polynomial commitment scheme

the universal cryptographic primitive. commit to a polynomial, prove evaluations, verify without seeing the polynomial. one primitive serves proof commitment, state authentication, noun identity, and data availability.

## the interface

```
trait PCS<F: Field> {
    fn commit(poly: &MultilinearPoly<F>) -> Commitment;     // 32 bytes
    fn open(poly: &MultilinearPoly<F>, point: &[F]) -> Opening;
    fn verify(commitment: &Commitment, point: &[F], value: F, proof: &Opening) -> bool;
}
```

three operations. commit is O(N). open produces a proof. verify checks the proof. all transparent (no trusted setup), all post-quantum.

## two backends

| | expander PCS | binary PCS |
|---|---|---|
| field | [[Goldilocks field\|Goldilocks]] ($\mathbb{F}_p$) | F₂ tower (via [[kuro]]) |
| encoding | expander-graph linear code | binary Reed-Solomon |
| commit | O(N) field ops | O(N) binary ops |
| proof size | O(log N + λ) ≈ ~1.3 KiB | workload-dependent |
| verify | O(λ log log N) ≈ ~660 field ops | O(λ log log N) binary ops |
| Merkle-free | yes | yes (hemera external) |
| primary use | arithmetic (12 [[nox]] languages) | bitwise (Bt, quantized Ten/Rs) |

both implement the same PCS trait. both fold into the same [[HyperNova]] accumulator via universal CCS with algebra selectors.

## three roles

the PCS serves three roles — all using the same interface:

**1. proof commitment.** commit to [[nox]] execution trace. [[SuperSpartan]] verifies constraints via [[sumcheck]]. [[HyperNova]] folds into accumulator.

**2. state commitment.** BBG_poly (10 public dimensions), A(x) (private commitments), N(x) (nullifiers). BBG_root = H(commit(BBG_poly) ‖ commit(A) ‖ commit(N)).

**3. noun identity.** every [[nox]] noun is a multilinear polynomial. noun identity = hemera(PCS.commit(noun) ‖ domain_tag) — 32 bytes. axis = PCS opening. DAS = PCS opening at random positions.

one interface. two backends. three roles.

see [[expander-pcs]] for the Goldilocks backend (recursive, Merkle-free). see [[binary-pcs]] for the F₂ backend. see [[accumulator]] for how both fold into one object.
