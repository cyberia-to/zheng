# SuperSpartan

the IOP layer in zheng. [[SuperSpartan]] is an Interactive Oracle Proof for [[CCS]] — Customizable Constraint Systems — a generalization that captures R1CS, Plonkish, and AIR in a single framework. by building on CCS, zheng handles any constraint format. this future-proofs the system: if a new arithmetization appears tomorrow, CCS already encodes it.

## why CCS matters

classical proof systems choose one arithmetization and commit to it. Groth16 speaks R1CS. PLONK speaks Plonkish gates. StarkWare speaks AIR. each choice locks the system into a particular constraint shape, and translating between them costs overhead.

CCS unifies all three. a CCS instance is a set of sparse matrices over a [[Goldilocks field]], combined with a multilinear structure that can express any constraint type. R1CS is three matrices with two terms. Plonkish is selector matrices with custom gate polynomials. AIR is shifted-row matrices encoding transition constraints. the encoding is direct — there is no translation layer, no overhead.

a proof system that handles CCS handles all of them simultaneously. zheng proves CCS instances, so zheng proves R1CS, Plonkish, and AIR without specializing.

## what matters for cyber: a relation compiled from the program

zheng does not prove a fixed register trace. the relation compiler turns a [[nox]] program and the shape of its subject into one CCS: every operand, intermediate value and output is a wire; field operations, conditionals, word operations and [[hemera]] rounds (degree-7 S-box rows) are CCS rows. the verifier compiles the same CCS from the program itself and places the public prefix `(1 ‖ io ‖ cycles)` — the constant, the inputs and outputs, and the cost — so only the witness half `w` is ever committed. for unbounded programs a uniform step relation (one CCS for one nox reduction step) lands with phase 3.

[[SuperSpartan]] verifies the compiled CCS via [[sumcheck]]: an outer sumcheck of the CCS degree over the rows, then an inner sumcheck that batches the matrix evaluations into one claim about `w̃`. every challenge is drawn from the cubic extension Fp3.

## sumcheck replaces zerofier division

classical STARKs verify constraints through a division argument. the constraint polynomial C(x) must vanish on every trace row, so the prover computes a quotient Q(x) = C(x) / Z(x), where Z is the vanishing polynomial over the trace domain. the prover then commits to Q and proves it has low degree. this works, but the division step requires NTT/FFT, and the quotient polynomial inherits the degree blowup from high-degree constraints.

[[SuperSpartan]] takes a different path. instead of dividing by the vanishing polynomial, it uses [[sumcheck]] to directly verify that the constraint polynomial sums to zero over all trace rows. the claim is simple: the sum of C evaluated at every row in the boolean hypercube equals zero. the [[sumcheck protocol]] reduces this claim — which ranges over 2^n rows — to checking C at a single random point. the polynomial commitment then opens the witness at that point.

the prover never computes a quotient polynomial. there is no zerofier, no division, no degree blowup from the division step.

## linear-time prover

the [[SuperSpartan]] prover performs only field operations during constraint verification. each sumcheck round requires evaluating the constraint polynomial at a few points and sending a univariate polynomial to the verifier. the total prover work is O(2^n) field multiplications and additions, where 2^n is the number of CCS rows.

critically, there is no NTT or FFT in the IOP layer. NTT cost appears only inside the commitment, when the prover Reed–Solomon-encodes the witness and generates the opening. the constraint verification itself — the part that scales with the number of patterns and the degree of each constraint — uses pure field arithmetic.

this separation matters. adding more patterns to [[nox]] or increasing their degree affects only the field arithmetic cost of the sumcheck, which is cheap. the cryptographic cost (hashing, Merkle paths, the opening) stays in the commitment and does not grow with constraint degree.

## high-degree constraints are free

in classical STARKs, a degree-d constraint polynomial produces a quotient of degree roughly d times the trace length. the prover must commit to this larger polynomial, which means more NTT work and a larger Merkle tree. degree-7 constraints (like the Poseidon2 rounds of [[hemera]]) cause a 7x degree blowup in the quotient — a substantial cost.

in [[SuperSpartan]], high degree affects only the number of field operations per sumcheck round. a degree-7 constraint means the prover sends degree-7 univariate polynomials (8 coefficients per round) instead of degree-1 polynomials (2 coefficients per round). the cost increase is 4x in field operations per round — but field operations are nanoseconds. there is no cryptographic cost increase, no larger Merkle tree, no additional hashing.

this is why zheng can afford hemera rounds as degree-7 rows. the Poseidon2 round function has high algebraic degree, and in a classical STARK this would be expensive to prove. in [[SuperSpartan]], the cost is a few extra field multiplications per sumcheck round.

## lens-agnostic design

[[SuperSpartan]] works with any polynomial commitment scheme (PCS), called a lens in zheng. the IOP reduces constraint satisfaction to a single polynomial evaluation claim: "the witness polynomial w̃, evaluated at random point r, equals value v." any lens that can commit to f and prove this evaluation completes the proof system.

plugging in [[WHIR]] gives zheng's succinct profile; plugging in a hiding Ligero-style Reed–Solomon tensor commitment (with Libra-masked sumchecks) gives the zk profile "veil". KZG or Dory would give other instantiations with other trust assumptions. the IOP stays the same.

for [[cyber]], the lens must be transparent, post-quantum and rest on [[hemera]] alone. the phase-2 bake-off of the [[soft3/proposals/proof-system-repair|proof-system repair]] ran two such lenses — TensorRs (RS tensor code, Ligero geometry) and WHIR — under the same Spartan transcript and fixtures; WHIR (rate 1/64, folding factor 4, 24 grinding bits) won both size classes and ships. the swap needed no change to the constraint system or the sumcheck protocol.

## the composition

the succinct profile in zheng:

```
nox program + statement (io, cycles)
         │
         ▼
    relation compiler → CCS (prover and verifier alike)
         │
         ▼
    WHIR_commit(w̃) → hemera Merkle root C
         │
         ▼
    Spartan over Fp3: outer + inner sumcheck
    reduces to: "w̃(r) = v"
         │
         ▼
    WHIR_open(w̃, r) → evaluation proof π
         │
         ▼
    verifier checks: sumcheck messages + WHIR_verify(C, r, v, π)
```

[[SuperSpartan]] occupies the middle of this pipeline. it takes the committed witness and produces a single evaluation claim. everything above it (compiling the relation, computing the witness, committing) is input preparation. everything below it (the opening and its verification) is the lens. the IOP is the bridge between computation and cryptography.

## references

- Setty, Thaler, Wahby. Customizable Constraint Systems for Succinct Arguments. ePrint 2023/552
- the original Spartan paper: Setty. Spartan: Efficient and General-Purpose zkSNARKs without Trusted Setup. CRYPTO 2020
- see [[sumcheck]] for the core protocol, [[polynomial-commitments]] for the lens, [[whirlaway]] for the architecture template
