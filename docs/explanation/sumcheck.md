# the sumcheck protocol

the sumcheck protocol is the heart of zheng. every proof that [[zheng]] produces, every constraint that [[SuperSpartan]] verifies, every relation compiled from a [[nox]] program — all of it flows through sumcheck. understanding sumcheck means understanding why proof systems can verify enormous computations in almost no time.

## the problem

imagine a [[polynomial]] f over k variables, where each variable takes values in {0, 1}. you want to prove that the sum of f over all 2^k binary inputs equals some claimed value T:

```
T = Σ f(x₁, x₂, ..., xₖ)
    over all (x₁, ..., xₖ) ∈ {0,1}ᵏ
```

the naive approach evaluates f at every binary input. that is 2^k evaluations — exponential in k. for a relation with 2^20 rows, that means roughly a million evaluations just to check one constraint. for 2^30 rows, a billion. the verifier would do as much work as re-executing the computation.

sumcheck compresses this to k rounds.

## the protocol

here is how the prover convinces the verifier that the sum really is T, one variable at a time.

```
claim: T = Σ_{x₁,...,xₖ ∈ {0,1}} f(x₁, x₂, ..., xₖ)

round 1:
  prover sends g₁(X₁) = Σ_{x₂,...,xₖ ∈ {0,1}} f(X₁, x₂, ..., xₖ)
  verifier checks: g₁(0) + g₁(1) = T
  verifier sends random challenge r₁

round 2:
  prover sends g₂(X₂) = Σ_{x₃,...,xₖ ∈ {0,1}} f(r₁, X₂, x₃, ..., xₖ)
  verifier checks: g₂(0) + g₂(1) = g₁(r₁)
  verifier sends random challenge r₂

  ...

round k:
  prover sends gₖ(Xₖ) = f(r₁, r₂, ..., r_{k-1}, Xₖ)
  verifier checks: gₖ(0) + gₖ(1) = g_{k-1}(r_{k-1})
  verifier sends random challenge rₖ

final check:
  verifier evaluates f(r₁, r₂, ..., rₖ) and checks it equals gₖ(rₖ)
```

each round, the prover "peels off" one variable. the sum over 2^k terms becomes a sum over 2^(k-1) terms, then 2^(k-2), and so on. after k rounds, everything reduces to a single evaluation of f at the random point (r₁, ..., rₖ).

the verifier never touches the 2^k terms. in each round, the verifier receives a univariate polynomial of low degree, checks one consistency condition, and sends back a single field element. k rounds, k checks, one final evaluation. done.

## why it works

the soundness of sumcheck rests on a simple fact about [[polynomials]]: a nonzero polynomial of degree d can have at most d roots. if the prover cheats — sends a gᵢ that is inconsistent with the actual sum — the verifier's random challenge rᵢ will catch the lie with overwhelming probability.

more precisely, if f has individual degree at most d in each variable, then each gᵢ has degree at most d. the prover would need the verifier to pick one of at most d "safe" values out of the field the challenges come from. the probability of escaping detection in any single round is at most d/|F|, and across k rounds at most kd/|F|. over the [[Goldilocks field]] alone (|F| = p ≈ 2^64) that is far from 128 bits — about 2^-56 for a Spartan IOP at 2^20 rows — so zheng draws every challenge from the cubic extension Fp3 (|F| = p³ ≈ 2^192), where the same IOP contributes about 2^-184 ([[zheng/specs/soundness|soundness ledger]]).

## the exponential compression

this is where the magic lives. the verifier performs O(k) work to check a claim about 2^k terms. that is an exponential-to-logarithmic reduction in verification cost. if the relation has 2^20 rows, the verifier does 20 rounds of simple field arithmetic instead of a million constraint checks. if it has 2^30 rows, 30 rounds instead of a billion.

the prover still does O(2^k) work — someone has to actually compute the sum. the asymmetry is the point. the prover does the heavy lifting once. the verifier checks it cheaply. this asymmetry is what makes [[proof systems]] practical.

## fiat-shamir: removing interaction

the protocol as described is interactive — the verifier sends random challenges after each round. real proof systems need to work without a live verifier. the [[Fiat-Shamir transform]] replaces the verifier with a hash function.

the prover maintains a transcript — a running hash of every message sent so far. each "random" challenge is derived by hashing the transcript. in [[zheng]], that hash is [[Hemera]] ([[Poseidon2]] over the [[Goldilocks field]]). the result is a non-interactive proof: a sequence of univariate polynomials that anyone can verify by re-deriving the challenges from the transcript.

```
transcript = []

for each round i:
  transcript.append(gᵢ)
  rᵢ = hemera_hash(transcript)
```

the security argument carries over in the random-oracle model: if every round is sound with error at most 2^-128, a prover making Q hash queries succeeds with probability about Q · 2^-128 (round-by-round soundness). zheng squeezes each Fp3 challenge limb from 192 bits of [[Hemera]] output, so each limb is within 2^-128 of uniform. the hash itself is the ledger's one conjectured cryptographic row.

## role in zheng

[[SuperSpartan]] uses sumcheck to verify the [[CCS]] compiled from a [[nox]] program. the core idea: instead of checking that every row of the relation is satisfied, SuperSpartan encodes the constraints as a multivariate polynomial and uses sumcheck to reduce the check to a single random evaluation.

the constraint polynomial vanishes on every row exactly when the witness satisfies the relation. an outer sumcheck (weighted by a random `eq` polynomial) proves that; an inner sumcheck batches the matrix evaluations it leaves behind. after both, the verifier needs one evaluation of the committed witness at a random point — which [[WHIR]] provides via a [[polynomial commitment]] opening.

two sumchecks, one commitment opening, one proof.

## sumcheck as nox arithmetic

here is the deepest connection in the stack. the operations inside a sumcheck round are pure [[Goldilocks field]] arithmetic: addition, multiplication, evaluation of low-degree univariate polynomials. these are exactly [[nox]] patterns 5 through 8 — the field arithmetic patterns of the virtual machine.

this means the sumcheck verifier itself can be written as a nox program, and so can the rest of the zheng verifier (the Merkle paths are hemera calls, a nox opcode). zheng's second verifier, in Trident, is such a program. it is used for composition — an old proof inside a new one — not to shrink proofs: the outer proof carries Merkle paths of its own. constant size for long computations comes from accumulation of evaluation claims (phase 3), which also runs on sumchecks: each step batches its claims with one.

## the sumcheck is the proof system

many modern proof systems — [[Spartan]], [[SuperSpartan]], [[Lasso]], [[Jolt]] — are built almost entirely from sumcheck instances composed together. the polynomial commitment scheme handles the final evaluation, but sumcheck does the structural work. in zheng, the sumcheck protocol carries the full weight of constraint verification. one WHIR opening seals the proof. everything between the relation and the opening is sumcheck.

this is why understanding sumcheck means understanding [[zheng]]. the rest is engineering around it.
