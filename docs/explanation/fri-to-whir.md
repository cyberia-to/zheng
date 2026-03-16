# from FRI to WHIR

the hash-based [[polynomial commitment schemes]] used in [[zheng]] have a lineage. [[FRI]] came first, establishing the paradigm. [[STIR]] refined it. [[WHIR]] perfected it. each generation learned from the last, and each achieved something the previous could not. this is the story of that evolution.

## FRI: the foundation

FRI (Fast Reed-Solomon Interactive Oracle Proof of Proximity) appeared in 2018, from Ben-Sasson, Bentov, Horesh, and Riabzev. the core idea: prove that a function committed via a Merkle tree is close to a low-degree polynomial, using only hashes and field arithmetic.

the protocol works by folding. the prover starts with evaluations of a polynomial of degree d over a domain of size n. in each round, the verifier sends a random challenge α, and the prover "folds" the polynomial — splitting into even and odd parts and combining them: f'(x) = f_even(x) + α · f_odd(x). the result is a new polynomial of half the degree over a domain of half the size.

```
round 0: polynomial f₀, degree d,   domain size n
round 1: polynomial f₁, degree d/2, domain size n/2
round 2: polynomial f₂, degree d/4, domain size n/4
  ...
round log(d): constant polynomial, domain size O(1)
```

after log(d) rounds, the polynomial has degree zero — a constant. the prover sends that constant. the verifier then spot-checks: pick random positions in the original domain, query the Merkle trees from each round, verify that the folding was done correctly. if the prover cheated at any round, the spot-checks catch it with high probability.

FRI established what hash-based commitment schemes could achieve: transparent (no trusted setup), post-quantum (relies only on collision-resistant hashing), and efficient prover (quasi-linear time). every STARK built between 2018 and 2024 used FRI or a close variant.

soundness comes from the field size: over the [[Goldilocks field]] (p = 2⁶⁴ − 2³² + 1), the error per query is roughly max_degree/|F|, which is negligible with ~30 queries per layer. the field's multiplicative subgroup of order 2³² enables FFTs up to length 2³² without extension fields — FRI folding operates on native 64-bit arithmetic.

the limitation is in the numbers. FRI operates at a fixed code rate — the ratio of the polynomial degree to the evaluation domain size stays constant across rounds. this rate determines how many queries the verifier needs for a given security level. at 128-bit security, FRI proofs run around 306 KiB with 3.9 ms verification time.

## STIR: tightening the rate

STIR (Shift To Improve Rate) appeared in 2024, from Arnon, Chiesa, Fenzi, and Yogev — the same research lineage. the key insight: there is no reason to keep the code rate constant across folding rounds.

in FRI, if you start at rate ρ, every round stays at rate ρ. in STIR, the rate increases with each round. a higher rate means the polynomial evaluations are more "spread out" relative to the domain, which means each verifier query extracts more information about proximity. fewer queries needed, smaller proofs.

```
FRI:    rate ρ → ρ → ρ → ρ → ... → ρ
STIR:   rate ρ → 2ρ → 4ρ → 8ρ → ... → 1
```

the mechanics change subtly. instead of folding onto a subdomain (a coset), STIR folds onto a shifted domain chosen to achieve the target rate. the algebraic structure of the [[Goldilocks field]] makes these shifts efficient — the multiplicative group has rich subgroup structure that STIR exploits.

the result: proofs shrink from 306 KiB to 160 KiB at 128-bit security. verification time stays similar at 3.8 ms. the prover does slightly more work per round (the shifting is more complex than simple folding), but proof size nearly halves. for systems where proof size matters — recursive verification, on-chain verification, bandwidth-constrained settings — this is a significant win.

the theoretical advance is in the query complexity. FRI queries scale as O(λ · log d) where λ is the security parameter and d the polynomial degree — security and degree are multiplicatively coupled. STIR decouples them: queries scale as O(λ/(−log(1−δ)) + log d), making the degree contribution additive rather than multiplicative. this is what enables smaller proofs.

STIR also introduced a cleaner theoretical framework. the rate schedule is a parameter: you can tune it for minimum proof size, minimum verification time, or a balance. this parameterization carries forward into WHIR.

## WHIR: the synthesis

WHIR (Weights Help Improve Rate) appeared in 2025, from Arnon, Chiesa, Fenzi, and Yogev — completing the trilogy. the key insight: use the algebraic structure of the [[sumcheck protocol]] to make each query round richer.

where STIR improved the rate schedule, WHIR improves what happens within each round. WHIR introduces weight polynomials — functions that reweight the evaluation domain in each round. these weights come from the sumcheck reduction: instead of treating proximity testing and evaluation proving as separate problems, WHIR fuses them.

```
FRI round:   fold using random challenge α
             query: check f₁(x) = fold(f₀(x), f₀(-x), α)

STIR round:  fold using α onto shifted domain
             query: check consistency on shifted evaluations

WHIR round:  fold using α with weight polynomial w(x)
             query: check weighted consistency
             each query proves proximity AND partial evaluation
```

the weight polynomials make each query carry more information. in FRI, a query checks one consistency relation. in WHIR, a query simultaneously checks proximity and contributes to the evaluation proof. this dual purpose means fewer total queries for the same security level.

the numbers tell the story:

```
scheme    proof size    verify time    security
────────────────────────────────────────────────
FRI       306 KiB       3.9 ms         128-bit
STIR      160 KiB       3.8 ms         128-bit
WHIR      157 KiB       1.0 ms         128-bit
```

proof size drops by half from FRI to STIR, and stabilizes at WHIR. verification time drops by nearly 4x from STIR to WHIR. that 1.0 ms verification is faster than [[KZG]] pairing checks — and WHIR achieves this with no trusted setup and post-quantum security.

WHIR verification at 1.0 ms is fast enough to run inside a [[nox]] program. this is what enables recursive proof composition in [[zheng]]: the WHIR verifier fits inside the prover, and the overhead is manageable. each recursive step adds roughly one millisecond of verification work to prove.

## the dual nature

FRI was designed as a proximity test — an IOPP (interactive oracle proof of proximity). to use it as a full [[polynomial commitment scheme]], you needed additional machinery to convert proximity claims into evaluation claims. this conversion added complexity and proof overhead.

STIR narrowed the gap. WHIR closed it entirely. WHIR is simultaneously an IOPP and a PCS. the weight polynomials encode the evaluation point directly into the proximity test. there is no separate evaluation protocol — the proximity test itself proves the evaluation.

```
FRI:   proximity test (IOPP) + separate evaluation → PCS
STIR:  tighter proximity test + separate evaluation → PCS
WHIR:  proximity test = evaluation proof → PCS directly
```

this unification simplifies [[zheng]] significantly. [[SuperSpartan]] reduces all constraints to one evaluation query via [[sumcheck]]. WHIR handles that query directly — proximity and evaluation in one protocol. no adapter layers, no conversion overhead.

## the stable interface

across all three generations, the external interface remains the same:

```
commit(polynomial) → commitment
open(polynomial, point) → (value, proof)
verify(commitment, point, value, proof) → bool
```

[[SuperSpartan]] calls commit and open. the [[sumcheck protocol]] runs between them. neither layer knows or cares whether FRI, STIR, or WHIR implements the commitment. the interface is a clean abstraction boundary.

this means [[cyber]] can upgrade its PCS without changing any layer above. when a future generation improves on WHIR — smaller proofs, faster verification, tighter security bounds — the upgrade is a swap at the commitment layer. the IOP, the constraint system, the VM trace encoding, the recursive verifier: all unchanged.

## why this lineage matters for zheng

the FRI-STIR-WHIR progression is a story of three insights compounding. FRI discovered that hash-based folding can prove proximity. STIR discovered that increasing the rate across rounds tightens proofs. WHIR discovered that weighting queries with sumcheck structure fuses proximity and evaluation into one protocol.

[[zheng]] builds on the final insight. the [[Whirlaway]] architecture — [[SuperSpartan]] IOP plus WHIR PCS plus [[sumcheck protocol]] — achieves transparent, post-quantum proofs with sub-millisecond verification. the prover runs in quasi-linear time over the [[Goldilocks field]]. the verifier checks a proof in one millisecond using only [[Hemera]] hashes and field arithmetic.

each generation of PCS made this architecture more viable. FRI made it possible. STIR made it compact. WHIR made it fast enough to recurse. and recursion is what turns a proof system into a foundation for [[planetary superintelligence]].
