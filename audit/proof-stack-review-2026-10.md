---
tags: zheng, audit, recursion, wrap, envelope, review
crystal-type: audit
crystal-domain: crypto
---
# proof stack — adversarial review before release/0.4, 2026-10-13

note (2026-10-27): the `.stands/` checkouts named below were removed in the cleanup of 2026-10-16; the revisions they held are named here, the directories are gone.

Review of the deltas not covered by the #52/#53/#56/#58 reviews: zheng #60
`feat/proof-stack` (bd244aa: #57 profile-6 envelope with the program bound
by digest, #59 GPU prover backends, the 26-bit size gate) and #61
`feat/split-key` (f814266: inner keys over the base field, chain
`4i:16,7i:22,9f:26`, format 5). Branch `fix/proof-stack-review` off
`feat/split-key`; stand `.stands/RV5` (the siblings of `.stands/V`, joy at
`feat/proof-stack` d31aa63). Stored proofs `.stands/V/proofs-k` (add.tri,
the shipped chain). Apple M4 Max, 48 GB, shared with a GPU agent.

## 1. verdict

No accepting attack on the shipped chain. One trust-base defect fixed
(the profile-5 verifier used an IVC key whose committed root the prover
backend computed); one ledger statement corrected. Every ledger row of the
three levels and the 64,213 B worst case recomputed independently.

| # | finding | severity | status |
|---|---|---|---|
| F1 | A verifier derives its IVC key in-process; committing the key words (one Merkle tree, coset leaves, 32 permutation batches ≥ 4096) runs on the process's prover backend (#59). Profile 5's decider opens the key words natively against that root. Under a backend returning wrong digests the derivation completes silently and the honest profile-5 proof is checked against another root (`recursion: whir: opening`); a reproducible device fault would let a prover open the key words to other values. Verification itself makes no backend call (counted: 0), and profile 6 is unaffected (its final key equals the prover's vk under a corrupting backend — the IVC key's root never enters it natively) | trust-base defect (needs a faulty or hostile device kernel; Metal derives the pinned keys) | fixed: `envelope::recursive::KEY_ROOTS` pins the key-word root of every verifier-facing IVC key (profile 5's 1/16 and 1/64 sets, profile 6's IVC at 16 bits); `recursive::key`, `keys::export` and `wrapped::final_key` refuse a derived key whose root is not pinned — fail closed. Tests `keys::the_pinned_ivc_key_roots_are_the_derived_ones`, `proof_stack_backend_derive` (fails before the fix: `recursive::key` returned the wrong key) |
| D1 | `specs/soundness.md` and `wrap::review` priced the inner levels with two key words (`groups [1, 1, 2]`, `2(fresh+1)+2` claims), the #58 configuration; #61 ships three (`[1, 1, 3]`, `+3`). Interactive weakest: level 0 **108.92** after 20 combination bits (stated 109.34 after 19), level 1 **102.35** (stated 102.76) — the chain's interactive minimum is level 1's combination, below the final level's 102.62. The final level's 102.62 is `fin`, not `shift_2` (104.00). Every priced row is unchanged and ≥ 128 (128.22 / 128.08 / 128.43) | doc / test | fixed: the review test derives the levels' configuration with `level_config` (three key words), `tests/proof_stack_review.rs` checks the derived keys' configs and figures; spec and audit text corrected |

## 2. attacks and checks

| item | attack | result | test |
|---|---|---|---|
| split key: sent limbs bound to the commitment | on both stored inner levels: limbs moved with the logical column kept (`p₀ − T·δ`, `p₁ + δ` on an Fp3 column) | the constraint check passes (the logical column is unchanged) and the proof is refused after it; at the new `γ_k` the identity `Σ_p eq(γ_k,p)·P_p(ρ) = Σ_w eq(γ_hi,w)·v_w` with the committed words' true `v_w` holds for the honest limbs and fails for the moved ones; `v_0` re-solved so the key claim holds → refused (shift reduction / opening), never at the constraints | `proof_stack_review::split_key_limbs_are_bound_to_the_committed_words` |
| split key: sent = committed | honest | the sent physical values are exactly `splitkey::at(key, ρ)` on both levels; 132 physical columns (108 + 2·12), three base words; the root a circuit constant pinned by `INNER_ROOTS` (re-checked by the prover in the fresh profile-6 prove below) | same |
| split key: canonical limbs | a key value's limb `+ p`, `u64::MAX` on the wire; one value too few; one key-word value too few | refused by the parser / `check_shape` before any verification | same |
| split key: recombination in-circuit | `logical` is generic over `Ops`: `scale_add(T, ·)`, `scale_add(T², ·)` are gate rows in the circuit interpreter, exact in the native one; absorbed before `γ_k`; limb 0 first by construction | sound (review); `splitkey::tests` | — |
| program digest substitution across levels | another program of the same geometry (one atom changed, same token count, inputs, output, cycles) | the IVC statement digest and so `X` move: level 0, level 1 and the final level all refuse the stored proofs; the honest statement with another program's digest refused by `verify_program` with either program; `from_bytes_for` → `ProgramMismatch` before the proof is parsed. The verifier derives the init entries from the program it is given after `with_program` checks the digest (hemera, domain `zheng-nox-program-v1`, canonical token encoding) | `proof_stack_review::a_substituted_program_is_refused_at_every_level`, `wrapped_envelope` (ignored) |
| key bundle, valid-looking other digest | well-formed bundles of real layouts: an IVC key of another step size; a final key of another chain (1/512, 30 bits, one level); layouts swapped; the IVC key twice; profile 6 without its final key | all refused by digest before parsing, nothing installed; the pinned export still installs | `proof_stack_review::a_well_formed_bundle_of_other_keys_is_refused`, `keys::a_tampered_bundle_is_refused` |
| size gate | proof one byte over `FinalProof::max_bytes(k)`; random bytes of exactly the bound; an envelope length prefix of 65,537 and of `2^63−1` | refused before parsing (`longer than its key allows`, `TooLarge`); no panic | `proof_stack_review::the_size_gate_refuses_before_parsing` |
| GPU vs CPU verify divergence | verifiers under a device-named recording backend (every device path, reference kernels), under Metal, under the CPU, under a backend corrupting every result: the stored IVC proof, both inner levels, the final proof, 24–48 decoded bit flips each (124 cases) | identical verdicts (4 honest accepted, 120 refused) under all four; the verifiers make **0** backend calls; keys derived under Metal are the pinned ones | `proof_stack_backend` (ignored; `ZHENG_REVIEW_BACKEND=metal`) |
| GPU in key derivation | derive under a corrupting backend | F1 | `proof_stack_backend_derive` |

## 3. ledger and size recomputed

An independent Python recomputation (the #58 reviewer's formulas, inner
rows updated for the split key: `γ_k` over 8 variables, five input words,
`2(fresh+1)+3` claims) reproduces the Rust rows of the derived keys (max
difference 0.005, rounding):

| level | queries | regimes | fold grinding | comb. | weakest (priced) | interactive weakest |
|---|---|---|---|---|---|---|
| inner 1/16, pow 16, `n = 16` | 58 / 33 / 23 / 18 | 11 / 7 / 6 / 3 | 16 / 14 / 15 / 11 | 20 | shift_2 128.22 | batch combine 108.92 |
| inner 1/128, pow 22, `n = 15` | 31 / 22 / 17 / 14 | 9 / 4 / 3 / 3 | 22 / 17 / 17 / 20 | 26 | shift_1 128.08 | batch combine 102.35 |
| final 1/512, pow 26, `n = 14` | 24 / 18 / 14 | 3 / 3 / 4 | 17 / 20 / 25 | — | fold_0 128.43 | fin 102.62 |

Worst-case final proof, from the recomputed schedule and the wire layout
(binary trees, every query a distinct leaf): header + nox-public claim
1,321 B + AIR messages 4,736 B + opening 58,156 B = **64,213 B** —
`wrap::max_proof_bytes` of the derived final key, which equals the stored
prover vk byte for byte.

## 4. runs

| run | result |
|---|---|
| `cargo test --release --workspace` (fix branch) | 360 passed, 0 failed, 17 ignored (lib 297 + 3 ignored); 478 s, 8.9 GB max RSS |
| `wrapped_envelope --ignored` (a fresh profile-6 prove of hash.tri, the prover's inner roots checked against `INNER_ROOTS`) | 4 passed; envelope 62,940 B; bit flips 3,036 tried, 2,492 decoded, 0 accepted; 95 s, 13.4 GB max RSS |
| `proof_stack_review --include-ignored` | 5 passed |
| `proof_stack_backend --ignored` (recording backend; Metal) | passed both |
| `wrap_fastverify_review --ignored` | 2 passed (241 cases × 12 threads × 3 rounds) |
| `transcript_pin`, `keys`, `recursive_envelope` | in the workspace run, passed; `keys::the_pinned_inner_roots_are_the_derived_ones` (ignored: the whole chain committed) passed, 40 s |
| joy `feat/proof-stack` d31aa63 over this branch: `cargo test --release --workspace` | 228 passed, 0 failed, 2 ignored |
| joy `wrapped_execution --ignored` (e2e profile 6) | passed, 82 s, 14.9 GB max RSS |
| soft3 conformance | not zheng-facing (no zheng dependency) — not run |
