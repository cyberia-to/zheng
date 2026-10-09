# performance characteristics

[[zheng]] proofs are hash-only: larger than pairing-based proofs, and smaller than the proofs production [[STARKs]] publish. this page gives the figures that have been measured, and states the goal separately. every number here comes from `audit/succinct-profile-2026-10.md` or `audit/zk-profile-2026-10.md` (Apple M4 Max, 16 cores, a machine shared with other jobs — times are upper bounds of a quiet machine; sizes are deterministic).

## proof sizes and verification time

| statement | profile | size | verify | proven bits |
|---|---|---|---|---|
| `add.tri` | public v3 (witness disclosed) | 185 B envelope | — | error 0 |
| `hash.tri` (one hemera hash) | public v3 (witness disclosed) | 6,463 B envelope | — | error 0 |
| `hash.tri` | succinct (Spartan + WHIR) | 15,921 B proof / 16,148 B envelope | 7.96 ms | 128 |
| synthetic relation, 2^20 rows | succinct (Spartan + WHIR) | 71,081 B | 270 ms | 128 |
| hash of a secret preimage | zk "veil" | 63.9 KB | 10.0 ms (4.1 ms with a cached verifying key) | 128.2 |

the public certificate of one hash shrank from 294,861 B (before phase 0 of the [[soft3/proposals/proof-system-repair|proof-system repair]]) to 15,608 B (phase 0) to 6,463 B (certificate v3). it stays linear in the witness: it is the sound fallback, not a succinct proof.

the succinct profile's WHIR parameters — rate 1/64, folding factor 4, 24 grinding bits — won the phase-2 bake-off against a Reed–Solomon tensor code (TensorRs) in both size classes. every proof is 128 proven bits; the derivation is in [[zheng/specs/soundness|the soundness ledger]].

## the goal

any nox computation → a proof ≤ 64 KB, post-quantum (hash-only), verified in ≤ 1 ms, constant in the number of steps; small statements ≤ 16–20 KB. where the measurements stand against it:

- size: one hash is inside the small-statement target; the 2^20 relation misses 64 KB by 11 %.
- verification: not met at any size. the causes, in order: hemera's speed inside the WHIR opening (most of the verifier's work is Merkle paths), an unstructured Spartan verifier (the matrices are evaluated generically), and recompiling the relation from the program on every verification — a cached verifying key removes the last (the zk profile drops from 10.0 to 4.1 ms with one).
- constant in the number of steps: comes with accumulation (phase 3, in progress); decider proof ≤ 64 KB goal; measured: the decider is 44–93 KB, but without recursion the whole proof grows with the steps — 83 KB (33 cycles), 146 KB (merkle-32), 384 KB (16,383 cycles, 3 segments), ~96 KB per 2^14-row segment (`audit/accumulation-2026-10.md`).

## prover time

the [[SuperSpartan|Spartan]] IOP is linear in the size of the relation: the [[sumcheck protocol]] streams through the hypercube variable by variable with no FFT. the commitment is not: Reed–Solomon encoding is an NTT over Goldilocks (O(N log N) field operations) and the Merkle tree costs one hemera hash per leaf group. for large relations the commitment and the WHIR rounds dominate. the zk profile proves the hash of a secret preimage in 143 ms.

## the hash inside the relation

[[hemera]] is Poseidon2 over Goldilocks, so hashing inside a relation is native field arithmetic — no bit decomposition. in the current relation compiler one hemera hash of a digest costs about 2,670 witness wires (degree-7 S-box rows). a public statement is capped at 32,768 rows, so the longest hash chain one statement admits is eleven hashes; longer computations need the uniform step relation of phase 3.

the same hash builds every Merkle tree and drives every Fiat–Shamir challenge. its speed outside the relation is the largest single factor in verification time today.

## comparison at 128-bit security

| system | proof size | setup | post-quantum |
|---|---|---|---|
| [[Groth16]] | 128 bytes | trusted (per-circuit) | no |
| [[PLONK]] | ~400 bytes | universal ceremony | no |
| production STARK chains (Stwo, Triton, RISC Zero) | 150 KB – 1 MB | transparent | yes |
| zheng succinct, one hash | 15,921 B | transparent | yes |
| zheng succinct, 2^20 rows | 71,081 B | transparent | yes |

pairing-based systems win on size by two to three orders of magnitude and lose on trust assumptions and quantum resistance. hash-only systems share zheng's model; zheng's proofs are smaller than the production chains' figures, and its verification is not yet faster than theirs.

## the Goldilocks advantage

the [[Goldilocks field]] p = 2^64 - 2^32 + 1 was chosen because its
arithmetic maps directly to 64-bit CPU instructions. addition is a
64-bit add with a conditional subtraction. multiplication uses the
CPU's native 64-bit multiply followed by a cheap reduction — the
special structure of the prime (a sparse polynomial in powers of two)
makes modular reduction a few shifts and adds rather than a full
division.

this eliminates the need for big-integer libraries. there is no
[[Montgomery multiplication]] overhead, no multi-limb carries, no
word-by-word schoolbook multiplication. every field operation is a
handful of native CPU instructions. this is why [[nebu]] exists as a
standalone library — the field implementation is performance-critical
and benefits from assembly-level optimization.

64 bits are too few for a challenge: zheng draws every challenge and evaluation point from the cubic extension Fp3 (p³ ≈ 2^192), which costs a few base-field multiplications per extension multiplication and only in the verifier-facing parts of the protocol.

## future: the Goldilocks field processor

the [[cyber]] roadmap includes a custom Goldilocks field processor —
silicon optimized for Goldilocks arithmetic and hemera hashing. since
hemera dominates both the prover's commitment and the verifier's Merkle
checks, hardware hemera is the lever that matters most; no figure is
claimed until it is measured.
