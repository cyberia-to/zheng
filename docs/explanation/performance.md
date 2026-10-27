# performance characteristics

[[zheng]] proofs are hash-only: larger than pairing-based proofs, and smaller than the proofs production STARK systems publish. this page gives the figures that have been measured, each with its audit, and states the goal separately. all were taken on an Apple M4 Max shared with other jobs: times are upper bounds of a quiet machine, sizes are deterministic. every figure was measured with zheng running hemera 0.3.1; the frozen hemera 0.4 (more rounds) moves them, and zheng adopts it in PR #69/#73.

## proof sizes and verification time

| statement | profile | size | verify | source |
|---|---|---|---|---|
| `hash.tri` (one hemera hash) | 0, public v3 (witness disclosed) | 6,463 B envelope | linear in the witness | `audit/succinct-profile-2026-10.md` (joy CLI test) |
| `hash.tri` | 1, succinct, shipped device parameters | 16,756 B | < 10 ms | soft3 `audit/proof-latency-2026-10.md` |
| Merkle membership, depth 16 / 32 | 1, succinct, device parameters | 59,722 / 64,071 B | 150 / 310 ms | same |
| `hash.tri` | 1, succinct, bake-off parameters (24 grinding bits) | 15,921 B proof / 16,148 B envelope | 7.96 ms | `audit/succinct-profile-2026-10.md` |
| synthetic relation, 2^20 rows | 1, succinct, bake-off parameters | 71,081 B | 270 ms | same |
| hash of a secret preimage | 2, zk "veil" | 63.9 KB | 10.0 ms (4.1 ms with a cached verifying key) | `audit/zk-profile-2026-10.md` |
| 33 cycles … 16,383 cycles | 4, machine (accumulation) | 83 KB … 384 KB, ~96 KB per `2^14`-row segment | 5.4–40 ms | `audit/accumulation-2026-10.md` |
| `hash.tri`, merkle-32 | 5, recursive (IVC) | 284,950 / 285,303 B, constant in the run | 26.5 / 32.1 ms | `audit/recursive-envelope-2026-10.md` |
| `add.tri` | 6, wrapped | 63,029 B; at most 64,213 B over every transcript | 1.9–2.2 ms (statement prepared) | `audit/ivc-speed-2026-10.md` |

every succinct, zk and recursive proof carries ≥ 128 proven bits with grinding counted; the derivations are in [[zheng/specs/soundness|the soundness ledger]].

the public certificate of one hash shrank from 294,861 B (before phase 0 of the [[soft3/proposals/proof-system-repair|proof-system repair]]) to 15,608 B (phase 0) to 6,463 B (certificate v3). it stays linear in the witness: it is the sound fallback, not a succinct proof.

the succinct profile's opening is WHIR, which won the phase-2 bake-off against a Reed–Solomon tensor code (TensorRs) in both size classes at rate 1/64, folding factor 4, 24 grinding bits (`succinct::params_for`). the default prover now uses `succinct::device_params`: rate 1/64, folding factor 4 up to `2^16` committed variables and 5 above, 16 grinding bits up to `2^17`, 22 at `2^18`, 24 beyond — the least grinding that keeps the proof ≤ 64 KB.

## the goal

any nox computation → a proof ≤ 64 KB, post-quantum (hash-only), verified in ≤ 1 ms, constant in the number of steps; small statements ≤ 16–20 KB; every proof a user device makes in ≤ 1 s. where the measurements stand against it:

- size: one-relation proofs fit 64 KB up to Merkle depth 32 (`2^18` committed variables) and miss it above; a run of any length fits it through profile 6 (≤ 64,213 B). one hash (16,756 B) sits just above the 16 KB stretch target.
- verification: not met by any profile. profile 6 verifies in about 2 ms, one-relation proofs in milliseconds to hundreds of milliseconds by size. the causes: hemera inside the WHIR opening (most of the verifier's work is Merkle paths), an unstructured Spartan verifier, and recompiling the relation on every verification — a cached verifying key removes the last.
- proving on the user's device: met on Metal for every product-shaped statement up to Merkle depth 16, cold and warm (hash.tri 0.07 s, depth 16 0.48 s; soft3 `audit/proof-latency-2026-10.md`); depth 32 takes 1.13 s cold. the wrap chain of profile 6 takes about 19 s on Metal and runs on aggregators, off the user's path (`audit/ivc-speed-2-2026-10.md`).

## prover time

the [[SuperSpartan|Spartan]] IOP is linear in the size of the relation: the [[sumcheck protocol]] streams through the hypercube variable by variable with no FFT. the commitment is not: Reed–Solomon encoding is an NTT over Goldilocks (O(N log N) field operations) and the Merkle tree costs one hemera hash per leaf group, and WHIR grinding is a search over hemera hashes. for large relations the commitment and the WHIR rounds dominate. provers run on CPU, Metal and WebGPU through lens's backends and produce the same bytes on each (`audit/prover-profile-2026-10.md`).

## the hash inside the relation

[[hemera]] is Poseidon2 over Goldilocks, so a permutation inside a relation is native field arithmetic. nox hashes nouns structurally — every atom is decomposed into 64 bits and hashed — so in the relation compiler one hemera hash of a digest costs about 2,700 constrained wires and a Merkle level about 5,000; the hemera node jet (`execution::node`) proves one Merkle level as one permutation (`audit/fast-path-2-2026-10.md`). one relation is capped at `2^20` rows (`MAX_RELATION`); longer runs use the machine of profiles 4–6.

the same hash builds every Merkle tree and drives every Fiat–Shamir challenge. its speed outside the relation is the largest single factor in verification time today.

## comparison at 128-bit security

| system | proof size | setup | post-quantum |
|---|---|---|---|
| Groth16 | 128 bytes | trusted (per-circuit) | no |
| PLONK | ~400 bytes | universal ceremony | no |
| production STARK chains (Stwo, Triton, RISC Zero) | 150 KB – 1 MB | transparent | yes |
| zheng succinct, one hash | 16,756 B | transparent | yes |
| zheng wrapped, a run of any length | ≤ 64,213 B | transparent | yes |

pairing-based systems win on size by two to three orders of magnitude and lose on trust assumptions and quantum resistance. hash-only systems share zheng's model; zheng's proofs are smaller than the production chains' published figures (soft3 `proposals/proof-system-repair.md` §1), and its verification is not yet faster than theirs.

## the Goldilocks advantage

the [[Goldilocks field]] p = 2^64 - 2^32 + 1 was chosen because its
arithmetic maps directly to 64-bit CPU instructions. addition is a
64-bit add with a conditional subtraction. multiplication uses the
CPU's native 64-bit multiply followed by a cheap reduction — the
special structure of the prime (a sparse polynomial in powers of two)
makes modular reduction a few shifts and adds rather than a full
division.

this eliminates the need for big-integer libraries. there is no
Montgomery multiplication overhead, no multi-limb carries, no
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
