> note: this page tells the evolution from FRI to STIR to WHIR. WHIR is the shipped commitment of zheng's succinct profile (rate 1/64, folding factor 4, 24 grinding bits), chosen in the phase-2 bake-off of the [[soft3/proposals/proof-system-repair|proof-system repair]]; the detour through "recursive Brakedown" is retired as unsound ([[zheng/docs/explanation/recursive-brakedown|recursive-brakedown]]). the figures below are the papers' published ones; zheng's measured figures are in `audit/succinct-profile-2026-10.md`.

# from FRI to WHIR

the hash-based [[polynomial commitment schemes]] used in [[zheng]] have a lineage. [[FRI]] came first, establishing the paradigm. [[STIR]] refined it. [[WHIR]] refined it further. each generation learned from the last, and each achieved something the previous could not. this is the story of that evolution.

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

soundness has two parts: the folding challenges (error roughly degree/|F| each — over the 64-bit [[Goldilocks field]] (p = 2⁶⁴ − 2³² + 1) too large for 128 bits, so challenges are drawn from an extension field; zheng uses Fp3) and the queries (each catches a far-from-code word with probability set by the rate and the decoding regime, so tens of queries are needed for 128 bits). the field's multiplicative subgroup of order 2³² enables FFTs up to length 2³² without extension fields — FRI folding operates on native 64-bit arithmetic.

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

fast verification also makes a verifier cheap to express as a program. zheng plans a verifier written as a [[nox]] program (in Trident) for composition — an old proof inside a new one, or proofs across domains. it is not used to shrink proofs: in a hash-only world the outer proof carries its own Merkle paths again. constant size for long computations comes from hash-based accumulation of Reed–Solomon claims instead (phase 3, ARC/WARP-style), whose decider is one WHIR opening.

## the dual nature

FRI was designed as a proximity test — an IOPP (interactive oracle proof of proximity). to use it as a full polynomial commitment scheme (PCS) — called a lens in zheng — you needed additional machinery to convert proximity claims into evaluation claims. this conversion added complexity and proof overhead.

STIR narrowed the gap. WHIR closed it entirely. WHIR is simultaneously an IOPP and a lens. the weight polynomials encode the evaluation point directly into the proximity test. there is no separate evaluation protocol — the proximity test itself proves the evaluation.

```
FRI:   proximity test (IOPP) + separate evaluation → lens
STIR:  tighter proximity test + separate evaluation → lens
WHIR:  proximity test = evaluation proof → lens directly
```

this unification is what zheng uses. [[SuperSpartan|Spartan]] reduces all constraints to one evaluation query via [[sumcheck]]. WHIR handles that query directly — proximity and evaluation in one protocol.

## the stable interface

across all three generations, the external interface remains the same:

```
commit(polynomial) → commitment
open(polynomial, point) → (value, proof)
verify(commitment, point, value, proof) → bool
```

[[SuperSpartan]] calls commit and open. the [[sumcheck protocol]] runs between them. neither layer knows or cares whether FRI, STIR, or WHIR implements the commitment. the interface is a clean abstraction boundary.

this means [[cyber]] can swap its lens without changing any layer above. the phase-2 bake-off did exactly that: TensorRs (a Reed–Solomon tensor code with Ligero geometry) and WHIR ran under the same Spartan transcript and the same fixtures, and WHIR won both size classes.

## why this lineage matters for zheng

the FRI-STIR-WHIR progression is a story of three insights compounding. FRI discovered that hash-based folding can prove proximity. STIR discovered that increasing the rate across rounds tightens proofs. WHIR discovered that weighting queries with sumcheck structure fuses proximity and evaluation into one protocol.

[[zheng]] builds on these insights. the succinct profile — [[SuperSpartan|Spartan]] over Fp3 plus one WHIR opening over Reed–Solomon codes and [[Hemera]] Merkle trees — is transparent and post-quantum, with 128 proven bits ([[zheng/specs/soundness|soundness ledger]]). measured on an Apple M4 Max: 15,921 B and 7.96 ms verification for one hemera hash, 71,081 B and 270 ms for a `2^20`-row relation. the goal is ≤ 64 KB for any nox computation and verification ≤ 1 ms; the size goal is missed by 11 % at `2^20` and the time goal is not met yet (hemera's speed inside the opening, an unstructured Spartan verifier, relation recompilation).

each generation of lens made this architecture more viable. FRI made it possible. STIR made it compact. WHIR fused evaluation into proximity, so one opening closes the proof.
