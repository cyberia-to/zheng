---
tags: zheng, soundness, security
crystal-type: entity
crystal-domain: comp
---
# soundness ledger

one row per component of a production profile: the assumption it rests on,
the bits claimed, whether that number is proven or conjectured, the argument,
and the parameter that controls it. a number appears here only if it is
derived on this page and checked by the named test. the release gate of the
proof-system repair (soft3 `proposals/proof-system-repair.md` §6) fails on any
"conjectured" row in a production profile; two rows below are conjectured, so
phase 1 does not pass that gate yet. The succinct profile (phase 2) adds no
conjectured row of its own: it inherits the relation-compiler and hash rows
exactly as public v3 does.

notation: `p = 2^64 − 2^32 + 1`, `log2 p = 63.9999999997`; `Q` = hemera
queries an attacker makes; "bits" = `−log2` of the success probability.

## production profiles

| component | assumption | bits claimed | status | argument | controlling parameter | test |
|---|---|---|---|---|---|---|
| public v3 certificate (`execution::certificate`, envelope profile 0) | none beyond the relation compiler: the verifier recompiles the CCS from the program, places `z[0] = 1`, inputs, outputs and cost itself, and evaluates every row exactly | soundness error 0 — the check is deterministic, no challenge is drawn | proven for the compiled relation | direct evaluation; specs/execution.md | — (limits: 4096 program nodes, 64 inputs, 4096 outputs, 2^20 columns) | `rs/tests/certificate_v3.rs`, `rs/tests/attack_fixtures.rs`, `certificate::malleability` |
| relation compiler (program + subject shape → CCS) | the compiled CCS is satisfiable with prefix `(1, io, cycles)` exactly when nox reduces the program to that output at that cost | — | conjectured (tested, not proven) | differential tests against native nox, mutated witnesses, malleability analysis (every movable wire only multiplies a zero factor) | — | `execution::relation::tests`, `execution::tagged::*`, `certificate::malleability` |
| state v3 certificate (`execution::state`, envelope profile 3) | as public v3, plus: every active read is answered by a state certificate the caller verified under `state_root` | error 0 in zheng; reads inherit the state certificate's binding | proven for the compiled relation; reads: see the hash row | verifier pins active flag, root limbs, namespace, key, value of every read and the root in the subject | `MAX_READS = 4096` | `execution::state_v3_tests`, `fixture_wrong_state_root_is_rejected` |
| succinct profile (`execution::succinct`, envelope profile 1) — composition | Spartan IOP over Fp3 (row below) + one PCS opening (rows below); Fiat–Shamir with hemera as a random oracle | interactive: `ε ≤ ε_IOP + ε_PCS`; at hash.tri (`m = 2^10`, `ℓ = 10`, `d = 7`, `t = 5`) `ε_IOP = 116/p³ = 2^-185.1`, `ε_PCS ≤ 2^-128.00` (WHIR 1/64, k = 4, 24 grinding bits, the shipped choice) → **128.0 bits, set by the PCS**; non-interactive: every component is round-by-round sound with per-round error ≤ `2^-128` (grinding included), so a prover making `Q` hemera queries succeeds with probability `≤ Q · 2^-128` plus hemera collisions (Merkle binding) | IOP and PCS bounds proven; the round-by-round → Fiat–Shamir step proven in the ROM (Canetti et al. 2019, round-by-round soundness); hemera-as-RO conjectured (hash row) | the verifier derives the relation and the pinned half `p` of `z' = (w ‖ p)` itself; only `w` is committed (specs/execution.md § succinct); the policy rejects any parameter set for which lens proves `< 128` bits at the proof's `ℓ` | PCS parameters (rate, folding factor, grinding, decoding), `ℓ`, `log m`, `d`, `t` | `tests/succinct_profile.rs`, `tests/succinct_bitflip.rs`, `execution::succinct::pcs::tests`, `spartan::reduce::tests` |
| succinct — Spartan IOP over Fp3 (`spartan::iop` + `spartan::reduce`, F = Fp3) | Schwartz–Zippel; sumcheck (Lund–Fortnow–Karloff–Nisan 1992) | `ε_IOP ≤ (log m · (d + 2) + 2(ℓ + 1) + t − 1) / p³`: outer sumcheck `log m` rounds of degree `d + 1`, `τ` by Schwartz–Zippel on `eq` (`log m / p³`), `γ` batching (`(t − 1)/p³`), inner sumcheck `ℓ + 1` rounds of degree 2; at `m = 2^20`, `ℓ = 20`, `d = 7`, `t = 5`: `226 / 2^192 = 2^-184.2`; round-by-round `(d + 1)/p³ = 2^-189` per round | proven | restoring the linear coefficient from the running claim accepts exactly the transcripts the full-polynomial verifier accepts | challenge field (Fp3), `d`, `log m`, `ℓ` | `spartan::reduce::tests`, `spartan::iop::tests` |
| succinct — WHIR opening (lens `Whir`, id 1) | Reed–Solomon proximity up to the Johnson bound; hemera Merkle trees binding | `security_bits(params, ℓ)` = min over WHIR's round-by-round terms (lens `WhirConfig::terms`), grinding included; the policy requires ≥ 128 | proven (lens `specs/whir.md`, WHIR eprint 2024/1586 Thm 5.2/7.5; Johnson-regime MCA from BCGM eprint 2025/2051 Lemma 9.3) | lens audit `rs-whir-pcs-2026-10.md` | rate, folding factor, grinding, `max_final_vars` | lens `rspcs` tests; `tests/succinct_bitflip.rs` |
| succinct — TensorRs opening (lens `TensorRs`, id 2) | Reed–Solomon proximity in the unique-decoding regime; hemera Merkle tree binding | `min(α round, column round)` from lens `TensorConfig`, grinding included; ≥ 128 by policy | proven (lens `specs/tensor-rs.md`) | as above | rate, grinding, shape | lens `rspcs` tests; `tests/succinct_bitflip.rs` |
| private MITH (`execution::zk`, `ZHMITH01`, envelope profile 2) | hemera commitments binding; Fiat–Shamir with hemera as a random oracle | interactive: `(2/3)^219 = 2^-128.107`, i.e. 128.1 bits; non-interactive (ROM): `≤ (Q + 1) · 2^-128.107` plus hemera collisions | interactive bound proven (3-special soundness of the ZKBoo (2,3)-decomposition, Giacomelli–Madsen–Orlandi 2016); ROM transform proven; hemera-as-RO conjectured; post-quantum (QROM) not claimed | specs/native-private-ccs.md | `REPETITIONS = 219` (218 would give 2^-127.5) | `zk::soundness_tests` |
| MITH challenges | hemera XOF output limbs uniform on F_p | trits exactly uniform | proven given the limbs | rejection: limbs `< p − 1`, `p − 1 ≡ 0 mod 3`, trit = limb mod 3 | — | `zk::soundness_tests::challenge_trits_come_from_an_exact_rejection_sampler` |
| transcript, base-field challenge (`Transcript::squeeze_challenge`, wide rule) | hemera XOF as a random oracle | statistical distance from uniform `≤ p / 2^192 < 2^-128` per limb for uniform bytes; exactly uniform for hemera's canonical-limb output | proven | each limb is a 192-bit integer (three output limbs) reduced mod p | 24 bytes per limb | `transcript::tests::reduce_192_is_the_integer_modulo_p`, `hemera_output_limbs_are_canonical` |
| transcript, extension challenge (`Transcript::squeeze_fp3`) | as above; `t³ − t − 1` irreducible over F_p | three limbs, each `< 2^-128` from uniform; field size `p³ = 2^191.9999999990` | proven | `gcd(x^p − x, t³ − t − 1) = 1` computed in the test | — | `field::tests::fp3_modulus_has_no_root_in_goldilocks`, `transcript::tests::fp3_challenges_*` |
| hash (hemera, 4-limb output) | collision resistance and random-oracle behaviour of Poseidon2 over Goldilocks with hemera's parameters | generic birthday bound `p^2 = 2^127.9999999993` classical; `p^(4/3) ≈ 2^85.3` quantum (BHT) | conjectured: parameters experimental, inverse-S-box partial rounds unanalysed (proposal §2, hash row) | generic bounds only | hemera round counts and output width (hemera repo) | — |

## informational

| component | assumption | bits | status | argument | controlling parameter | test |
|---|---|---|---|---|---|---|
| the Spartan IOP over Goldilocks challenges | as the Fp3 row | `227 / 2^64 = 2^-56.2` at `m = n = 2^20` | proven, and too small for a 128-bit claim: no profile uses it | as the Fp3 row | — | `spartan::iop::tests::goldilocks_iop_agrees_with_the_same_relation` |

## retired

| component | status |
|---|---|
| legacy folded trace API (`commit`, `open`, `verify_eval`, `verify`, `fold`, `decide`, `ccs`, `folding`, `phi`; feature `legacy`, off by default) | retired — unsound: the fold is unchecked, the statement is unbound and the constant wire is free (specs/decider.md §soundness; `retired_path_hole_*` tests pass because the path is broken); Brakedown's code distance is unproven (lens#6) |
| direct proofs: public v2 (`verify_execution`), state v1 (`StateStatement::verify`) | retired — read for one release (`JOYEXEC2`, `JOYST001`). acceptance rests on the exact check of the complete table that PublicTensor authenticates under a hemera Merkle root (hash row); their Spartan transcript uses the 0.4.0 challenge rule (`Transcript::new_v1`, Goldilocks, 2^-56 at the sizes above) and is a consistency check only |
