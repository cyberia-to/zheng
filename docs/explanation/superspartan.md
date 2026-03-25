# SuperSpartan

the IOP layer in zheng. [[SuperSpartan]] is an Interactive Oracle Proof for [[CCS]] — Customizable Constraint Systems — a generalization that captures R1CS, Plonkish, and AIR in a single framework. by building on CCS, zheng handles any constraint format. this future-proofs the system: if a new arithmetization appears tomorrow, CCS already encodes it.

## why CCS matters

classical proof systems choose one arithmetization and commit to it. Groth16 speaks R1CS. PLONK speaks Plonkish gates. StarkWare speaks AIR. each choice locks the system into a particular constraint shape, and translating between them costs overhead.

CCS unifies all three. a CCS instance is a set of sparse matrices over a [[Goldilocks field]], combined with a multilinear structure that can express any constraint type. R1CS is three matrices with two terms. Plonkish is selector matrices with custom gate polynomials. AIR is shifted-row matrices encoding transition constraints. the encoding is direct — there is no translation layer, no overhead.

a proof system that handles CCS handles all of them simultaneously. zheng proves CCS instances, so zheng proves R1CS, Plonkish, and AIR without specializing.

## what matters for cyber: AIR

for [[cyber]] specifically, AIR is the relevant arithmetization. [[nox]] is a reduction machine with 16 deterministic patterns. each pattern defines a transition constraint: given the register values at row t, what must be true at row t+1. pattern 5 (add) says the result register equals the sum of two operand registers. pattern 7 (mul) says the result is the product. pattern 15 (hash) says consecutive rows satisfy the round equations of [[hemera]] (Poseidon2).

these transition constraints form an AIR instance. [[SuperSpartan]] encodes them as a CCS instance and verifies them all via [[sumcheck]].

## sumcheck replaces zerofier division

classical STARKs verify constraints through a division argument. the constraint polynomial C(x) must vanish on every trace row, so the prover computes a quotient Q(x) = C(x) / Z(x), where Z is the vanishing polynomial over the trace domain. the prover then commits to Q and proves it has low degree. this works, but the division step requires NTT/FFT, and the quotient polynomial inherits the degree blowup from high-degree constraints.

[[SuperSpartan]] takes a different path. instead of dividing by the vanishing polynomial, it uses [[sumcheck]] to directly verify that the constraint polynomial sums to zero over all trace rows. the claim is simple: the sum of C evaluated at every row in the boolean hypercube equals zero. the [[sumcheck protocol]] reduces this claim — which ranges over 2^n rows — to checking C at a single random point. Brakedown then opens the trace commitment at that point.

the prover never computes a quotient polynomial. there is no zerofier, no division, no degree blowup from the division step.

## linear-time prover

the [[SuperSpartan]] prover performs only field operations during constraint verification. each sumcheck round requires evaluating the constraint polynomial at a few points and sending a univariate polynomial to the verifier. the total prover work is O(2^n) field multiplications and additions, where 2^n is the trace length.

critically, there is no NTT or FFT in the IOP layer. NTT cost appears only inside Brakedown when the prover commits to the trace polynomial and generates evaluation proofs. the constraint verification itself — the part that scales with the number of patterns and the degree of each constraint — uses pure field arithmetic.

this separation matters. adding more patterns to [[nox]] or increasing their degree affects only the field arithmetic cost of the sumcheck, which is cheap. the cryptographic cost (hashing, evaluation proofs) stays in Brakedown and does not grow with constraint complexity.

## high-degree constraints are free

in classical STARKs, a degree-d constraint polynomial produces a quotient of degree roughly d times the trace length. the prover must commit to this larger polynomial, which means more NTT work and a larger Merkle tree. degree-7 constraints (like the Poseidon2 rounds in [[nox]] pattern 15) cause a 7x degree blowup in the quotient — a substantial cost.

in [[SuperSpartan]], high degree affects only the number of field operations per sumcheck round. a degree-7 constraint means the prover sends degree-7 univariate polynomials (8 coefficients per round) instead of degree-1 polynomials (2 coefficients per round). the cost increase is 4x in field operations per round — but field operations are nanoseconds. there is no cryptographic cost increase, no larger Merkle tree, no additional hashing.

this is why [[nox]] can afford a hash pattern with degree-7 transition constraints. the Poseidon2 round function has high algebraic degree, and in a classical STARK this would be expensive to prove. in [[SuperSpartan]], the cost is a few extra field multiplications per sumcheck round.

## PCS-agnostic design

[[SuperSpartan]] works with any polynomial commitment scheme. the IOP reduces constraint satisfaction to a single polynomial evaluation claim: "the trace polynomial f, evaluated at random point r, equals value v." any PCS that can commit to f and prove this evaluation completes the proof system.

plugging in recursive Brakedown as the PCS gives the zheng architecture. plugging in a different PCS — KZG, Dory, Ligero — would give a different instantiation with different tradeoffs. the IOP stays the same.

for [[cyber]], recursive Brakedown is the right choice: transparent setup, post-quantum security, sub-millisecond verification, and hash-only assumptions that align with [[hemera]]. but the PCS-agnostic design means zheng can swap commitment schemes without rewriting the constraint system or the sumcheck protocol.

## the composition

the full pipeline in zheng:

```
nox execution trace (2^n rows × 16 columns)
         │
         ▼
    encode as multilinear polynomial f
         │
         ▼
    Brakedown_commit(f) → commitment C
         │
         ▼
    SuperSpartan sumcheck: verify AIR constraints
    reduces to: "f(r) = v"
         │
         ▼
    Brakedown_open(f, r) → evaluation proof π
         │
         ▼
    verifier checks: sumcheck transcript + Brakedown_verify(C, r, v, π)
```

[[SuperSpartan]] occupies the middle of this pipeline. it takes the committed trace and produces a single evaluation claim. everything above it ([[nox]] execution, trace encoding, Brakedown commitment) is input preparation. everything below it (Brakedown opening, verification) is the PCS. the IOP is the bridge between computation and cryptography.

## references

- Setty, Thaler, Wahby. Customizable Constraint Systems for Succinct Arguments. ePrint 2023/552
- the original Spartan paper: Setty. Spartan: Efficient and General-Purpose zkSNARKs without Trusted Setup. CRYPTO 2020
- see [[sumcheck]] for the core protocol, [[polynomial-commitments]] for the PCS, [[whirlaway]] for the historical architecture
