> note: Whirlaway (SuperSpartan + WHIR) is the template of zheng's succinct profile as shipped after the [[soft3/proposals/proof-system-repair|proof-system repair]] (2026-10): Spartan over Fp3 plus one WHIR opening. the detour through "recursive Brakedown" is retired as unsound — see [[zheng/docs/explanation/recursive-brakedown|recursive-brakedown]].

# Whirlaway

a proof architecture that composes three protocols — the [[sumcheck protocol]], [[SuperSpartan]], and [[WHIR]] — into one multilinear, hash-only proof system. proposed by LambdaClass (2025). zheng's first design followed it, left it for an expander-code commitment that turned out to have no real opening, and came back to it: the succinct profile (envelope profile 1) is Spartan + WHIR.

this article is about assembly: how the pieces fit together.

## the pipeline, as zheng runs it

```
┌─────────────────────────────────────────────────────────┐
│  1. COMPILE   program + subject shape → CCS             │
│               verifier and prover compile the same one  │
│               public prefix (1 ‖ io ‖ cycles) pinned    │
│                                                         │
│  2. WITNESS   prover runs nox, fills the free columns w │
│                                                         │
│  3. COMMIT    w̃ as a multilinear polynomial,            │
│               RS-encoded, one hemera Merkle root C      │
│                                                         │
│  4. PROVE     Spartan over Fp3: outer sumcheck of the   │
│               CCS degree, inner sumcheck batching the   │
│               matrix evaluations → one point r          │
│                                                         │
│  5. OPEN      WHIR_open(w̃, r) → evaluation proof π      │
│               proves w̃(r) = v, Merkle paths per query   │
│                                                         │
│  6. VERIFY    recompile (or load the verifying key),    │
│               check both sumchecks + WHIR_verify        │
└─────────────────────────────────────────────────────────┘
```

the prover performs stages 1 through 5; the verifier performs 1 and 6. the verifier never sees the witness — only the commitment C, the sumcheck messages, the matrix evaluations and the opening π.

## why multilinear

classical univariate STARKs encode each column of a trace as a separate univariate polynomial and pay one commitment and one opening per column (or batch them).

Whirlaway encodes everything committed as one multilinear polynomial over the Boolean hypercube. one polynomial, one commitment, one opening. in zheng that polynomial is the witness half `w` of `z' = (w ‖ p)`; the public half `p` is computed by the verifier and never committed.

## stage by stage

### compile

the relation compiler turns the nox program and the shape of its subject into a [[CCS]] of degree up to 7 (hemera's S-box). matrices depend only on the program and the subject shape, never on witness values. the verifier compiles it itself; the verifying key is a hemera digest of the relation and is absorbed into the transcript.

### commit

the prover Reed–Solomon-encodes the evaluations of `w̃` over Goldilocks and builds a [[hemera]] Merkle tree over the codeword. the root is the commitment.

### prove

Spartan's outer sumcheck reduces "every CCS row holds" to one random point; the inner sumcheck batches the matrix evaluations into one claim about `w̃`. every challenge is drawn from Fp3 (`p³ ≈ 2^192`), so the IOP contributes about 2^-185 at the measured sizes ([[zheng/specs/soundness|soundness ledger]]).

### open

WHIR proves `w̃(r) = v`: rounds of folding with out-of-domain samples and in-domain queries, each query authenticated by a Merkle path. zheng ships rate 1/64, folding factor 4, 24 grinding bits — 128 proven bits.

### verify

the verifier checks the sumcheck messages against the running claims, recomputes the public half's contribution, and checks the WHIR opening against the root. any bit flipped in a proof is rejected (bit-flip scans: 0 accepted).

## measured

Apple M4 Max, shared machine, `audit/succinct-profile-2026-10.md`: one hemera hash (`hash.tri`) — 15,921 B proof, verify 7.96 ms; a synthetic `2^20`-row relation — 71,081 B, verify 270 ms. the goal of the repair is ≤ 64 KB for any nox computation and verify ≤ 1 ms; neither is met at `2^20` yet. most of the proof is the opening's Merkle paths, most of the verify time is hemera inside the opening, the unstructured Spartan verifier, and recompiling the relation.

## Whirlaway in context

the name reflects the composition: WHIR provides the polynomial commitment, SuperSpartan the IOP, the sumcheck protocol drives both. zheng's instantiation is [[Goldilocks field]] arithmetic from [[nebu]], Poseidon2 hashing from [[hemera]], the nox relation compiler, Fp3 challenges, and a public prefix the verifier places itself.

what Whirlaway does not give is constant size for unbounded computations. zheng gets that from a separate layer: hash-based accumulation of Reed–Solomon evaluation claims (ARC/WARP-style, phase 3, in progress), whose decider is one WHIR opening of the final accumulator. a verifier written as a nox program is planned for composition only — in a hash-only world a proof of a proof carries its own Merkle paths again and does not get smaller.

## the PCS lineage

- FRI (2018): the original Reed–Solomon proximity proof; each round halves the degree by random folding; many Merkle paths per opening.
- STIR (2024): out-of-domain constraints per round shrink the query count and the proof.
- WHIR (2024): weighted constraints let the same protocol prove evaluations of multilinear polynomials, with fewer queries; the shipped opening of zheng's succinct profile.

the literature's figures for each of these are in [[zheng/docs/explanation/fri-to-whir|fri-to-whir]] and [[zheng/docs/explanation/whir|whir]]; zheng's own measured figures are in `audit/`.

## references

- Habock, Levit, Papini. Whirlaway: a multilinear STARK. LambdaClass, 2025
- see [[superspartan]] for the IOP layer, [[trace-to-proof]] for the execution-to-evidence pipeline
- see [[polynomial-commitments]] for the commitment, [[sumcheck]] for the core protocol
