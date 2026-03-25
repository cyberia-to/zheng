> **NOTE:** this document describes the historical Whirlaway architecture (SuperSpartan + WHIR). zheng has evolved to use recursive Brakedown instead of WHIR. see reference/ for the current architecture.

# Whirlaway (historical)

the original proof architecture of zheng. Whirlaway composed three protocols — the [[sumcheck protocol]], [[SuperSpartan]], and [[WHIR (legacy)]] — into a single proof system that turned [[nox]] execution traces into succinct cryptographic evidence. proposed by LambdaClass (2025), implemented by zheng for [[cyber]].

this article is about assembly: how the pieces fit together and why the composition was elegant.

## the pipeline

a [[nox]] program runs, produces a trace, and zheng proves that the trace is valid. six stages:

```
┌─────────────────────────────────────────────────────────┐
│  1. EXECUTE   nox runs program                          │
│               produces execution trace: 2^n × 16        │
│                                                         │
│  2. ENCODE    trace → multilinear polynomial            │
│               f(x₁, ..., x_{n+4}) over Goldilocks      │
│                                                         │
│  3. COMMIT    Brakedown_commit(f) → commitment C        │
│               one Hemera Merkle root                    │
│                                                         │
│  4. PROVE     SuperSpartan sumcheck                     │
│               all AIR constraints → one point r         │
│                                                         │
│  5. OPEN      Brakedown_open(f, r) → evaluation proof π │
│               proves f(r) = v                           │
│                                                         │
│  6. VERIFY    check sumcheck transcript                 │
│               + Brakedown_verify(C, r, v, π)            │
└─────────────────────────────────────────────────────────┘
```

the prover performs stages 1 through 5. the verifier performs only stage 6. the verifier never sees the trace — only the commitment C, the sumcheck transcript, and the evaluation proof π.

## why multilinear

classical univariate STARKs encode each column of the trace as a separate univariate polynomial. an execution trace with M columns requires M polynomial commitments, M evaluation proofs, and M openings during verification.

zheng encodes the entire trace — all rows and all columns — as a single multilinear polynomial. a trace with 2^n rows and 2^4 = 16 columns becomes f(x₁, ..., x_{n+4}), where the first n variables index the row and the last 4 variables index the column. one polynomial. one commitment. one opening.

this collapses the verification cost. instead of M separate PCS checks, the verifier performs one Brakedown verification. the proof size drops correspondingly: one evaluation proof instead of M.

## stage by stage

# execute

[[nox]] runs the program. each reduction step produces one row: 16 registers holding the pattern tag, operand hashes, result, focus counters, and auxiliary values. the trace grows until focus reaches zero or the program halts. the raw trace has an arbitrary number of rows.

# encode

the trace is padded to 2^n rows (the next power of two). padding rows repeat the halted state — they satisfy the AIR constraints trivially because the halted pattern's transition is the identity.

the padded trace (2^n × 16) is interpreted as evaluations of a multilinear polynomial f over the boolean hypercube {0,1}^{n+4}. for any binary string (b₁, ..., b_n, c₁, ..., c₄), the value f(b₁, ..., b_n, c₁, ..., c₄) equals the entry at row (b₁...b_n) and column (c₁...c₄). the polynomial is the unique multilinear extension of this table — it agrees with the trace on all binary inputs and extends smoothly to the full [[Goldilocks field]].

# commit

the prover evaluates f over a suitable domain and constructs a Merkle tree using [[hemera]] (Poseidon2). the root of this tree is the commitment C. this is Brakedown's commit phase: one hash, one root, binding the prover to the entire trace.

# prove

[[SuperSpartan]] takes over. each of [[nox]]'s 16 patterns contributes a transition constraint. the constraint polynomial combines them all, weighted by pattern selectors so that only the active pattern's constraint applies at each row. the claim: this combined constraint sums to zero over all 2^n rows.

the [[sumcheck protocol]] reduces this claim across n rounds. each round, the prover sends a univariate polynomial and the verifier responds with a random challenge. after n rounds, the exponential sum has been reduced to a single evaluation: "f at random point r equals value v." this is where the IOP ends and the PCS begins.

# open

Brakedown proves the evaluation claim. the prover generates an opening proof π demonstrating that the committed polynomial f, evaluated at the random point r chosen by the sumcheck, yields the value v. this involves the recursive Brakedown protocol that gives zheng its speed advantage.

# verify

the verifier checks two things: the sumcheck transcript is consistent (each round's univariate polynomial matches the running claim), and the Brakedown evaluation proof is valid (the commitment C, point r, value v, and proof π all check out). if both pass, the verifier is convinced that the [[nox]] trace is valid — without ever seeing the trace itself.

## the elegant closure

something remarkable happens when you examine what the verifier actually computes.

the sumcheck verification is field arithmetic: check that univariate polynomials satisfy degree bounds and that gᵢ(0) + gᵢ(1) equals the running claim. this is [[nox]] patterns 5 through 8 — add, sub, mul, div over the [[Goldilocks field]].

the Brakedown verification is hashing and Merkle path checking. hashing is [[nox]] pattern 15 (the Poseidon2 hash jet). Merkle path verification is the merkle_verify jet. the Fiat-Shamir transcript — which makes the interactive protocol non-interactive — uses [[hemera]] to derive challenges from the proof data.

every operation the verifier performs is a [[nox]] primitive. the verifier IS a nox program. this means zheng proofs can be verified inside zheng — recursive composition. a proof that a proof is valid costs one more [[nox]] execution, which produces one more trace, which zheng proves. the recursion bottoms out at a single proof that the on-chain verifier checks.

## Whirlaway in context

Whirlaway was proposed by LambdaClass in early 2025 as a multilinear STARK architecture. the name reflects the composition: WHIR (legacy) provided the polynomial commitment, SuperSpartan provided the IOP, and the sumcheck protocol was the engine driving both.

zheng is [[cyber]]'s implementation. the specific choices — [[Goldilocks field]] arithmetic from [[nebu]], Poseidon2 hashing from [[hemera]], 16-pattern reduction machine from [[nox]] — are cyber's instantiation of the abstract Whirlaway template. other implementations might choose different fields, different hash functions, different VMs. the architecture remains the same.

## what makes it work

three properties converge.

the [[sumcheck protocol]] is algebraic: it uses only field operations, so the prover is linear-time and the verifier is logarithmic-time.

Brakedown is hash-based: it uses only Merkle trees and Reed-Solomon proximity testing, so it requires no trusted setup and provides post-quantum security.

[[SuperSpartan]] is universal: it handles any CCS instance, so [[nox]]'s AIR constraints — regardless of pattern count or constraint degree — are verified without specialization.

the combination gives zheng transparent setup, post-quantum security, sub-millisecond verification, and a linear-time prover. each property comes from a different layer of the architecture, and they compose cleanly because the layers are independent.

## why Brakedown

Brakedown (recursive) replaced WHIR (legacy) as the PCS for zheng. Brakedown is Merkle-free — it eliminates the Merkle tree overhead that dominated WHIR verification cost. the evolution from [[FRI]] to [[STIR]] to WHIR (legacy) to recursive Brakedown traces a line of increasing efficiency:

- FRI (2018): the original proximity proof. each round halves the polynomial degree via random folding. verification requires checking many Merkle paths — 5,600 hashes at 128-bit security for a single opening.
- STIR (2024): reinterprets FRI rounds as constraint-satisfaction over out-of-domain points. reduces proof size (160 KiB vs 306 KiB) by folding more aggressively, but verification time stays similar (~3.8 ms) because Merkle path checking dominates.
- WHIR (legacy) (2025): introduced weighted queries — instead of uniform random sampling, the verifier places higher weight on positions that carry more information. verification dropped to ~1.0 ms at 128-bit security.
- Brakedown (recursive): Merkle-free polynomial commitment. eliminates the Merkle tree bottleneck entirely.

the practical consequence: recursive Brakedown is the polynomial commitment scheme that combines transparent setup (hash-only, no ceremony), post-quantum security (no discrete log assumptions), and sub-millisecond verification. KZG is faster to verify but requires a trusted ceremony and breaks under quantum attack. IPA needs no ceremony but verification takes ~10 ms. FRI and STIR are transparent and post-quantum but verify 4x slower.

for [[cyber]], verification speed is the critical parameter. every recursive proof composition step runs the verifier as a [[nox]] program. Brakedown's efficient verifier makes recursion practical — with FRI's ~280,000 constraint verifier, each recursion level would take 4x longer, and proof aggregation for a 1000-transaction block would be prohibitively expensive.

## references

- Habock, Levit, Papini. Whirlaway: a multilinear STARK. LambdaClass, 2025
- see [[superspartan]] for the IOP layer, [[trace-to-proof]] for the concrete execution-to-evidence pipeline
- see [[polynomial-commitments]] for the polynomial commitment scheme, [[sumcheck]] for the core protocol
