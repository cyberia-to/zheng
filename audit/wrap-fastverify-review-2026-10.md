---
tags: zheng, audit, recursion, wrap, review
crystal-type: audit
crystal-domain: crypto
---
# wrap fast verifier — adversarial review, 2026-10-10

Review of zheng #58 (`feat/wrap-fastverify` 379eda2, stacked on #56
`feat/wrap` 606cda1): streamed commitments, key words committed once per
key, the chain `4i:16,8i,9f:24`, message digests in the final level's
transcript, the compiled constraint graph and its used key columns, the
wiring closing by slot, the permutation memo of the parser, the
persistent verifier pool, parallel sumchecks. Branch
`fix/wrap-fastverify-review` (stand `.stands/RV4`: the siblings of
`.stands/V`). Apple M4 Max, 48 GB, shared machine (load 60–115).

## 1. verdict

No accepting attack on the shipped chain. One binding defect (message
digests not length-binding) fixed; two hardenings (field-native closing
shortcuts reachable by a circuit interpreter; a loaded key's successor
columns unchecked against its graph) fixed. One spec attribution
corrected. Every ledger row of the three levels recomputed independently.

| # | finding | severity | status |
|---|---|---|---|
| F1 | `msg` digest: a part zero-pads its last block and the last sponge did not absorb the length, so `m` and `m ‖ 0` of the next length up share a digest (found by `message_digests_bind_length_order_and_content`: length 9 vs 10, `[…, x]` vs `[…, x, 0]`). `soundness.md` claimed a second message with one digest is a hemera collision — false across lengths. Not exploitable in #58: every message length is the key's (`check_shape`: `final_poly` `2^fv`, `local` `V1`, `next` `next_cols`; the parser reads fixed counts) | binding defect, latent | fixed: the last sponge absorbs the length first (no extra permutation on the shipped proofs: 107 single permutations as before); final-level transcript change |
| F2 | the direct opening's closing check (#58) reads every weight, `α` and the final polynomial out with `value()` and re-enters the sum as `constant()` whenever `cfg.direct()`; in a circuit interpreter that leaves the closing unconstrained. Only the native final verifier opens one word today (`derive_key_wrap` refuses a final-mode inner level), so unreachable | hardening | fixed: `Ops::native()`; the field-native closing runs for a native interpreter only, a circuit takes the generic per-constraint path; `Point::Native` and final-mode `wrap::verify` assert a native interpreter |
| F3 | a key loaded from bytes kept `next_cols` as read: a key sending fewer successor columns than its graph reads would zero them in `G` while the column-batching row assumes the claim covers every read column | hardening (a loaded key is trusted as its bytes) | fixed: `check_vk` refuses `next_cols` ≠ the graph's read successor columns (inner: all) and `key_cols` ≠ the graph's |
| D1 | `soundness.md`: "104.70 (the final level's `fold_1` after its 24-bit fold grinding)" — the final level's 104.70 is `shift_1` after 24 query-grinding bits; `fold_1` carries 22 fold bits (106.40 interactively). The shipped-levels test asserted the final level only; its comment gave 104.00 for the 1/16 level (109.34 measured) | doc | fixed: text, and the test asserts all six figures |

## 2. attacks and checks

| item | attack | result | test |
|---|---|---|---|
| 1 streamed commitment | commit coefficients `A` streamed; open a leaf whose symbols are recomputed from `B` (one coefficient changed; another word) with `A`'s path; immediate and batched (memo-reading) Merkle checks; the memo pre-filled with both leaves' permutations | refused; honest accepted. The verifier never sees coefficients: an opening is symbols + path to the absorbed root; streaming is the prover's memory layout only. Streamed digests = held digests, streamed leaves = `encode_*` | `fastverify_review::a_streamed_opening_binds_to_the_committed_codeword_not_to_the_coefficients`, `stream::tests`, `word::tests::streamed_leaf_digests_equal_the_held_codeword_s` |
| 2 key words once per key | reuse across keys / statements | sound: `kw` is a field of the key it was derived for (`kw.root = key_root`); the verifier opens the key claims against the key's `key_root` as a circuit constant — a constant gate (`qk`) in the next level's preprocessed columns, so the final vk's sparse columns pin every inner level's root; per-proof data (`x`, roots, OOD) enter the transcript as before. A key loaded from bytes has no `kw` and its prover recommits (same root). The words are public: reuse leaks nothing | review; `tests/wrap.rs` |
| 3 message digests | length, order, limb, split | F1 (fixed); order, every limb, a dropped item, a swap → other digest; absorbed before `g_l, g_n` (columns) and before the query grinding (final polynomial); prover and verifier agree (`msg::tests`, `tests/wrap.rs`) | `message_digests_bind_length_order_and_content` |
| 4 used key columns | a constraint reading a skipped column | sound: `key_cols` = `used_inputs()` of the key's own graph (derived, or recomputed from the graph's bytes on load — never from the proof); every unused input of `G` (key, local, successor), perturbed alone or all at once, leaves `G` and its compiled form unchanged; every listed key column moves `G`; final mode reads 64 of 108 key columns, inner 108; compiled graph = graph (7,506 / 8,023 operations) | `the_compiled_graph_is_the_graph_and_skipped_key_columns_are_never_read`, `a_loaded_key_must_send_the_successor_columns_its_graph_reads`, `tests/wrap_fastverify_review.rs` (shipped vk) |
| 5 wiring by slot | slot form ≠ per-cell `u_λ` | equal for every `|α| ≤ n` on random wirings (multi-cell slots, `T`/`T²`, writes without reads) and on the shipped wiring (49,333 reads, 23,892 writes, `|α| = 12`); the slot form declines (per-cell path) when `|α| > n`, a general coefficient, cells out of slot order, a read of two writes, a slot over two rows | `the_slot_closing_is_the_per_cell_closing`, shipped vk test |
| 6 Merkle memo | parse-time permutations reused by the check (TOCTOU) | sound: the memo maps a full 16-lane input to hemera's output, filled only by computing the permutation (`permute_many_remember`), keyed by exact limbs; a hit is the permutation whatever proof filled it; the check still hashes the symbols and path it verifies to the absorbed root. Parser batched leaf digests = the verifier's sponge (widths 1–40, both fields); recall = permutation under 8 threads with clears past the cap | `the_parser_s_batched_leaf_digests_are_the_verifier_s_sponge`, `the_permutation_memo_returns_only_permutations_under_concurrency` |
| 7 ledger | recompute | §3 | `review::the_shipped_wrap_levels_…` (all six figures), shipped vk test |
| 8 threads | races in accept/reject | 241 cases (the honest proof + 240 decoded single-bit flips) × 12 threads × 3 rounds, interleaved: every result — accept, and the first failed check's message — equals one verifier alone. Field sums are order-free; `map_chunks` returns in order; the first failing Merkle group is taken in order; the pool's caller runs every task it posts (a newer job overwriting the slot cannot strand one) | `tests/wrap_fastverify_review.rs::concurrent_verifiers_accept_and_refuse_as_one_verifier_alone` |
| — direct closing | native vs generic | the native direct closing = the generic per-constraint closing (eq, pow, row-column inside `α` and spilling into the final variables, every round) | `whir::tests::the_native_direct_closing_is_the_generic_closing` |

## 3. ledger recomputed

An independent Python recomputation of lens's formulas (WHIR schedule
derivation — regime, OOD, fold grinding, queries — and every term:
`ood_i`, `comb_0`, `fold_i`, `shift_i`, `fin`, the batch's `γ`,
sumcheck, combination with its grinding; the wrap rows) reproduces the
Rust ledger row by row (max difference 0.005, the printout's rounding)
and the same schedules:

| level | rows | queries | regimes (Johnson m) | fold grinding | comb. grinding | weakest (priced) | interactive weakest (every grinding removed) |
|---|---|---|---|---|---|---|---|
| inner 1/16, pow 16, `n = 16` | 27 | 58 / 33 / 23 / 18 | 11 / 7 / 6 / 3 | 16 / 14 / 15 / 11 | 19 | shift_2 128.22 | batch combine 109.34 |
| inner 1/256, pow 24, `n = 15` | 27 | 27 / 20 / 16 / 13 | 5 / 3 / 3 / 3 | 20 / 18 / 21 / 23 | 24 | shift_1 128.29 | shift_1 104.29 |
| final 1/512, pow 24, `n = 14` | 17 | 24 / 18 / 15 | 5 / 4 / 3 | 22 / 22 / 22 | — | fold_1 128.40 | shift_1 104.70 (fold_1: 106.40) |

The interactive figures subtract every grinding the ledger prices: fold
(`fold_i − fold_pow_i`), query (`shift_i`, `fin` − the previous round's
`query_pow`) and combination (`batch combine − comb_pow`); the other
rows carry none. The shipped final key (vk bytes) gives the same rows;
with its actual 49,333 reads the wiring row is 176.41 (the test's
`2^18` gives 174.00). `wrap::SHIPPED`, the keys `wrap_bench` derives
(53,042 / 26,089 / 15,606 rows → `2^16 / 2^15 / 2^14`) and the review
test's levels are one chain.

## 4. runs

| run | result |
|---|---|
| `cargo test --release -p zheng --lib` | 288 passed, 3 ignored |
| `wrap_bench add.tri` (stored IVC, wrap 0, wrap 1; final level re-proved under the new transcript) | final proof 63,641 B (opening 57,584), wrap 2 prove 50.3 s at load ≈ 95, max RSS 15.0 GB |
| `wrap_verify add.tri` (vk derived 147 s, 8,978,744 B — byte-identical to `.stands/V`'s) | verify warm median 6.59 ms (min 4.21, 41 runs, load 95), main-thread CPU 4.49 ms; 107 single + 1,493 batched permutations |
| `tests/wrap_fastverify_review.rs --ignored` | 2 passed (23 s) |
| `tests/wrap.rs` (chain at 1/16, final mode, new transcript) | passed, 190 s, 9.3 GB max RSS |
| `tests/wrap_review.rs` (546 tampers) | passed, 176 s, 10.4 GB max RSS |
| bit-flip scan of the re-proved final proof (`wrap_flip add.tri`, 16 threads) | 509,128 flips, 508,284 decoded, **0 accepted**, 716 s |
| a final proof of `feat/wrap-fastverify` under this branch | refused (`recursion: grinding`): the transcript changed; stored final proofs must be re-proved (inner proofs and keys unchanged) |
