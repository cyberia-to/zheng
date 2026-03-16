# the sumcheck protocol

the sumcheck protocol is the heart of zheng. every proof that [[zheng]] produces, every constraint that [[SuperSpartan]] verifies, every trace that [[nox]] generates — all of it flows through sumcheck. understanding sumcheck means understanding why proof systems can verify enormous computations in almost no time.

## the problem

imagine a [[polynomial]] f over k variables, where each variable takes values in {0, 1}. you want to prove that the sum of f over all 2^k binary inputs equals some claimed value T:

```
T = Σ f(x₁, x₂, ..., xₖ)
    over all (x₁, ..., xₖ) ∈ {0,1}ᵏ
```

the naive approach evaluates f at every binary input. that is 2^k evaluations — exponential in k. for a [[nox]] execution trace with 2^20 rows, that means roughly a million evaluations just to check one constraint. for 2^30 rows, a billion. the verifier would do as much work as re-executing the computation.

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

more precisely, if f has individual degree at most d in each variable, then each gᵢ has degree at most d. the prover would need the verifier to pick one of at most d "safe" values out of an entire [[Goldilocks field]] of size p = 2^64 - 2^32 + 1. the probability of escaping detection in any single round is at most d/p, which is negligible. across k rounds, the total soundness error is at most kd/p — still negligible for any practical k and d.

## the exponential compression

this is where the magic lives. the verifier performs O(k) work to check a claim about 2^k terms. that is an exponential-to-logarithmic reduction in verification cost. if the nox trace has 2^20 rows, the verifier does 20 rounds of simple field arithmetic instead of a million constraint checks. if the trace has 2^30 rows, 30 rounds instead of a billion.

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

the security argument carries over: if the prover cannot predict the hash output, the challenges are effectively random. [[Hemera]] provides 128-bit security, which is more than enough.

## role in zheng

[[SuperSpartan]] uses sumcheck to verify [[AIR]] constraints over [[nox]] execution traces. the core idea: instead of checking that every row of the trace satisfies every constraint, SuperSpartan encodes the constraints as a multivariate polynomial and uses sumcheck to reduce the check to a single random evaluation.

the constraint polynomial C(x) vanishes on the trace if and only if the trace is valid. sumcheck proves that the sum of C over all trace rows is zero. after k rounds, the verifier needs just one evaluation of C at a random point — which [[WHIR]] provides via a [[polynomial commitment]] opening.

one sumcheck, one commitment opening, one proof.

## sumcheck as nox arithmetic

here is the deepest connection in the stack. the operations inside a sumcheck round are pure [[Goldilocks field]] arithmetic: addition, multiplication, evaluation of low-degree univariate polynomials. these are exactly [[nox]] patterns 5 through 8 — the field arithmetic patterns of the virtual machine.

this means the sumcheck verifier itself can be written as a nox program. a small one. and that nox program can be proved by another sumcheck. this is the recursion: a proof whose verifier is itself a provable computation. the sumcheck verifier verifies a sumcheck, verified by another sumcheck, all the way down.

```
nox trace → sumcheck proof → verifier (nox program) → sumcheck proof → ...
```

recursive composition becomes possible precisely because the verification algorithm lives inside the same computational model that the proof system proves. the sumcheck protocol makes verification cheap enough to fit inside the prover, and [[nox]] makes the prover's computation provable. the circle closes.

## the sumcheck is the proof system

many modern proof systems — [[Spartan]], [[SuperSpartan]], [[Lasso]], [[Jolt]] — are built almost entirely from sumcheck instances composed together. the polynomial commitment scheme handles the final evaluation, but sumcheck does the structural work. in zheng, the sumcheck protocol carries the full weight of constraint verification. [[WHIR]] seals the proof with a single opening. everything between the trace and the opening is sumcheck.

this is why understanding sumcheck means understanding [[zheng]]. the rest is engineering around it.
