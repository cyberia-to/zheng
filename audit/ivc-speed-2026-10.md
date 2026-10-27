---
tags: zheng, audit, recursion, ivc, wrap, performance, review
crystal-type: audit
crystal-domain: crypto
---
# IVC step and wrap chain speed, with its review — 2026-10-14

superseded by hemera 0.4 (2026-10-16): the hemera figures below (x⁻¹ partial rounds, 8 + 16 rounds, 144 constants, ~736 constraints) describe the 0.3 record; the frozen profile is x⁷ in every round, 6 + 6 + 48 rounds, 240 constants, ~1,440 constraints — `hemera/audit/profile-0.4-2026-10.md`.

note (2026-10-27): the `.stands/` checkouts named below were removed in the cleanup of 2026-10-16; the revisions they held are named here, the directories are gone.

Owner directive (2026-10-14): proving ≤ 1 s. User-device proofs take the
fast path (profile 1, another branch); this round owns the recursive
path — the IVC step per segment and the profile-6 wrap chain. Targets:
IVC step ≤ 1 s per segment on Metal, wrap chain ≤ 5 s on Metal, then lower.

Branches: zheng `feat/ivc-speed` off `release/0.4` (f35e13b), lens
`feat/ivc-speed` off `release/0.2` (5796e50). Stand `.stands/IVC`
(siblings: nox `release/0.4`, hemera/strata/tade/honeycrisp `main`).
Baseline = the same fixtures built from the base commits (`.stands/IVC/base`).
Apple M4 Max (12P + 4E), 40-core GPU, 48 GB, macOS 26.4, rustc 1.95.0,
`--release`. Quiet machine for the tables (1-minute load 3–7 at the
start of each block; the GPU idles at ~30 % from the desktop).

## 1. results

### IVC (profile 5/6 recursion), hash.tri — one step of 2^15 rows and the decider (`ivc_bench`)

| | base Metal | **Metal** | base WebGPU | **WebGPU** | base CPU | **CPU** |
|---|---|---|---|---|---|---|
| step (pre-commit + circuit + prove + self-check) | 3.45 s | **1.19–1.21 s** | 5.31 s | **2.26–2.32 s** | 5.72 s | **2.77–2.81 s** |
| decider (once per run) | 1.23 s | **0.67 s** | 1.80 s | 0.99 s | 1.56 s | 0.94 s |
| IVC prove | 4.68 s | **1.86–1.90 s** | 7.10 s | **3.24–3.26 s** | 7.29 s | **3.71–3.76 s** |
| process CPU | 9.8 CPU-s | 7.2 CPU-s | 10.3 | 7.7 | 87 | 42.5 |
| proof | 347,197 B | 518,905 B (4-ary paths, 1/8) | | same bytes | | same bytes |

New step on Metal, phase by phase (ms, wall): pre-commit 97 · circuit 72
· trace 8 · word b 93 · word c 102 · zerocheck 352 · deferred folds 18 ·
shift 6 · accumulation sumcheck 123 · accumulator commit 301 · openings
and grinding 12 · self-check (included) — 1,188.

### wrap chain (profile 6), add.tri (`wrap_bench`, keys derived in-process)

| | base Metal | **Metal** | base WebGPU | **WebGPU** | base CPU | **CPU** |
|---|---|---|---|---|---|---|
| IVC prove | 4.59 s | **1.92 s** | 6.93 s | 3.36 s | 7.92 s | 4.31 s |
| wrap 0 / 1 / 2 | 6.20 / 15.53 / 19.59 s | **3.60 / 7.63 / 12.47 s** | 6.95 / 24.86 / 34.50 s | 6.30 / 24.01 / 27.01 s | 7.63 / 31.32 / 44.76 s | 7.24 / 19.19 / 36.11 s |
| **wrap chain** | 41.3 s | **23.7 s** | 66.3 s | 57.3 s | 83.7 s | 62.5 s |
| key derivation (once per chain: IVC + 3 levels) | 0.6 + 1.7 + 4.3 + 0.2 s | 0.3 + 0.9 + 3.2 + 0.2 s | 1.1 + 2.5 + 8.1 + 0.2 s | 0.4 + 2.3 + 7.6 + 0.2 s | 1.1 + 2.7 + 8.4 + 0.2 s | 0.6 + 2.6 + 9.2 + 0.2 s |
| whole process | 53.4 s, 103 CPU-s | **31.0 s, 53 CPU-s** | 85.3 s | 71.5 s | 104.2 s, 1,385 CPU-s | 79.5 s, 1,095 CPU-s |
| peak RSS | 13.0 GB | 10.5 GB | 12.7 GB | 13.4 GB | 12.6 GB | 11.4 GB |
| final proof | 62,965 B | 63,029 B | | same bytes | | same bytes |
| final proof bound (every transcript) | 64,213 B | **64,213 B** | | | | |
| verify (statement prepared) | 1.9 ms | 1.9–2.2 ms | | | | |

The base run of this table measured 41.3 s on Metal; the quiet base run
of the morning 37.1 s (`audit/prover-profile-2026-10.md` §4d: 34.5 s).

Same bytes: IVC proof `01cfef5e…`, wrap 0 `2931bd82…`, wrap 1
`d3a1e805…`, wrap 2 `c7bff6d2…`, final `7580817e…` — SHA-1 equal on Metal,
WebGPU and CPU; hash.tri IVC `59bfc9c5…` on all three. Every
engineering-only commit was checked against the base bytes before the
format changed (hash.tri `6b158176…`, add.tri `dbb617f9…` equal to
`release/0.4` on all three backends).

## 2. what changed

| commit | change | kind | effect (Metal) |
|---|---|---|---|
| lens b21e1a2 | `Backend::coset_leaves_kept`: a held codeword committed in one device pass (coset NTTs, leaf sponges, values copied out); Metal, WebGPU, checked/spot/record wrappers | engineering | the held commit's interleave, lane layout and copies leave the CPU |
| lens b21e1a2 | grinding dispatches start at `2^bits` and double to `2^22` (were `2^16`, then `2^22`) | engineering | a 16-bit grind cost 4 M nonces in a third of the calls: IVC grinding 396 → 46 ms |
| lens b21e1a2 | `prof-*` backends: wall time per device operation (`LENS_PROFILE_EACH=1` per call) | tooling | the measurements below |
| zheng 68f779c | held words through `stream::commit` (device takes every coset group; CPU only for declined groups — a CPU worker's coset was ~30× a device group's share); codeword kept coset-major; pre-committed words a kept for their steps (2 GiB budget, `ZHENG_KEEP_WORDS_BYTES`); circuit trace without the key, permutation rows and phase 2 in threads; line folds in threads | engineering | step 3.45 → 2.3 s |
| zheng fb96ee7 | **every IVC tree 4-ary**; **profile 6's IVC at rate 1/8** (`ivc::SHIPPED_RATE`) | soundness-relevant (format) | step circuit 29,628 → 24,259 rows at 1/8 (20,348 at 1/16); every step word half the 1/16 codeword; step 2.3 → 1.55 s |
| zheng 18d63c6 | **field-native WHIR schedules rebalanced** (`recursion::whir::schedule`) | soundness-relevant (schedule) | final level grinding work 2^28.3 → 2^27.7, level 1 2^26.7 → 2^25.0 |
| zheng f6ee2a4 | accumulation sumcheck over borrowed base/Fp3 tables (mixed first round); base spot points' eq tables in mixed arithmetic; the accumulator's combination and every Möbius transform in threads | engineering | step 1.55 → 1.39 s |
| lens 8f94ce8 / zheng bd1c5f1 | `LineSession::columns`; zerocheck rounds of ≤ 256 pairs on the CPU (the device round's ~11 ms latency floor); transposes, column packing, successor columns and the shift combination in threads | engineering | step 1.39 → 1.17 s |

Formats: IVC key layout `ZHKIVC02`, `RECURSIVE_FORMAT` 3,
`WRAPPED_FORMAT` 6. Re-derived on the CPU backend: `KEY_ROOTS` (the three
IVC sets; unchanged by the schedule), `INNER_ROOTS`, `RECURSIVE_DIGEST`,
`WRAPPED_DIGEST` (`examples/wrap_keys`: "roots match the pins").

### structural options measured, and the choice

| option | measured / planned | decision |
|---|---|---|
| 4-ary IVC trees | path permutations halve: step circuit −9,280 rows at 1/16; prover nodes a third; IVC proof +27 % (multi-opening siblings) | **taken** |
| IVC rate 1/8 (with 4-ary) | words half the 1/16 codeword; 77 spot checks; circuit 24,259 rows; wrap 0 48,453 rows (2^16) | **taken** (profile 6) |
| IVC rate 1/4, 20 grinding bits | circuit 32,677 of 32,768; combination grinding 2^23 per step (~0.25 s); wrap 0 63,671 rows | rejected: grinding eats the saving, no headroom |
| smaller segments (2^14) | step circuit ≥ 18,535 rows at any rate/grinding (`ivc_plan`) > 16,384 | infeasible |
| final circuit 2^13 (2-level or smaller final) | final circuit ≥ 13,778 rows over any inner rate tried (`wrap_chain`: 1/128…1/1024 inner, 3 and 4 levels) | infeasible without a new final circuit |
| per-round grinding budget (audit wrap-fastverify §10) | generalised: per round the regime and both grindings for the least work at lens's queries | **taken** (`whir::schedule`) |
| final level 4-ary | siblings ×1.5 → over the 64 KiB gate | rejected |
| parallel step proving (accumulation tree) | not built: the step circuit would verify two proofs (≈ 2× rows: 48 K at 1/8, over 2^15) — needs n = 16 steps or a smaller verifier | open |

## 3. where the time goes now (Metal, `prof-metal`)

**The chain is hemera-bound.** Wrap 2 (12.2–12.5 s): coset leaves 5.5 s
(217 M leaf permutations: one base word of 2^29 symbols, Fp3 rounds of
2^28 and 2^27), Merkle levels 2.0 s (59 M nodes), grinding 3.8 s
(145 M nonces this run; 218 M expected), zerocheck 0.14 s, CPU ≈ 0.8 s.
Device permutations run at 35–40 M/s (`gpu_bench`: grind 45 M/s); the
chain is ≈ 93 % device time. The 1/512 final codeword and its size gate
fix the permutation count: ≈ 500 M permutations ≈ 12 s at this kernel.

**The step** (1.19 s): device ≈ 0.75 s — three base words (pre-commit,
b, c: 2^24 symbols, 2.1 M leaf + 0.35 M node permutations each,
≈ 70 ms), the Fp3 accumulator (6.3 M + 0.35 M permutations ≈ 200 ms),
zerocheck line sums 227 ms (the interpreter: round 0 105 ms for 114,688
evaluations of 12,311 operations); CPU on the critical path ≈ 0.45 s —
circuit build 72 ms, accumulation sumcheck 123 ms (eq tables of 88
claims over 2^21), zerocheck column assembly ~100 ms, the rest in
threads.

## 4. review (soundness-relevant changes: 4-ary IVC trees, rate 1/8, rebalanced schedules)

### attacks

| attack | result | test |
|---|---|---|
| a spot check's 4-ary siblings permuted within a node group (all four words) | refused | `ivc_speed_review::four_ary_paths_bind_their_leaves_and_positions` |
| a sibling taken from another level | refused | same |
| another leaf's opening at a query's position | refused (word 0 of a one-step proof is the zero accumulator: every leaf opens alike, the substitution is the honest opening — checked, and the two-step proof (tree-12) attacks a committed accumulator) | same |
| a path one node short / long | refused natively; through the wire the multi-opening carries each distinct sibling once, so a length-only tamper re-encodes to the honest bytes (accepted only then) | same |
| the decider's 4-ary openings (accumulator tree, key-word tree, final queries): siblings swapped, a sibling limb, a symbol | refused | same |
| zero accumulator: `ZeroWord::new(layout, 4-ary)` vs the committed all-zero word | root and every opening equal | `ivc_speed_review::the_zero_accumulator_is_the_committed_zero_word` |
| rebalanced schedules: queries vs lens's, every term ≥ 128 at every shipped level and the IVC decider | equal queries; all ≥ 128 | `ivc_speed_review::rebalanced_schedules_keep_lens_queries_and_reach_128_bits`, `whir::schedule::tests` |
| existing suites under the new shapes: `recursion` tamper set, `recursion::review` (forged state, unbound public input), `proof_stack_review`, `wrap_review`, `wrap_fastverify_review`, envelopes | see §4 runs | — |

### ledger, recomputed independently

`audit/ivc-speed/ledger.py` (Python, from the WHIR/BCGM formulas and
the printed round specs only, no zheng code) reproduces the Rust rows:

| level | rounds: regime · queries · query/fold grinding | comb. | weakest (priced) | interactive weakest |
|---|---|---|---|---|
| IVC decider 1/8, pow 16, ℓ 21, 3 words | J13·77·17/12, J9·38·17/11, J7·26·14/11, J7·19·16/13 | 15 | shift_2 128.04 | 111.04 (decider shift_2) |
| IVC accumulation 1/8 | t 77, query 16, comb 17 | | spot 128.08 | combine 111.19 |
| level 0, 1/16, pow 16, 5 words | J7·58·18/11, J7·33·16/14, J4·23·17/11, J3·18·16/11 | 15 | shift_3 128.09 | 110.23 |
| level 1, 1/128, pow 22, 5 words | J5·31·24/17, J4·22·22/17, J3·17·22/17, J3·14·20/20 | 21 | shift_1 128.24 | 104.24 |
| final, 1/512, pow 26 | J5·24·24/22, J4·18·24/22, J3·14·27/22 | — | fold_1 128.40 | 101.89 (fin after 27 bits) |

Every priced row ≥ 128 (Python and Rust agree to 0.01). The tree fan-in
changes no IOP row; Merkle binding is the words row (4-ary nodes as in
the inner wrap levels since #56). Final proof bound 64,213 B
(`wrap::max_proof_bytes`, unchanged: queries unchanged).

### bit flips

| proof | flips | decoded | accepted |
|---|---|---|---|
| final (add.tri, shipped chain, `wrap_flip`) | 504,232 (every bit) | 503,437 | **0** (336 s) |
| IVC (add.tri, rate 1/8, 4-ary, `ivc_flip`, stride 4) | 1,033,458 | 1,032,390 | **0** (1,955 s) |

### runs (final HEAD of `feat/ivc-speed`)

| run | result |
|---|---|
| `cargo test --release --workspace` | 367 passed, 0 failed, 17 ignored |
| `ivc_speed_review` (new) | 3 passed |
| `keys -- --ignored` (the prover's chain against `INNER_ROOTS`, the bundle against `WRAPPED_DIGEST`) | passed |
| `proof_stack_review --include-ignored` (stored proofs of this chain) | 5 passed (split-key limbs, substituted program at every level, bundles, size gate, ledgers) |
| `wrap_fastverify_review --ignored` | 2 passed |
| `proof_stack_backend --ignored` (Metal; recording and corrupting backends) | passed: no backend moves a verdict |
| `wrapped_envelope --ignored` (fresh profile-6 prove of hash.tri, inner roots checked) | 4 passed, bit-flip sample 0 accepted; 97 s, 10.7 GB |
| `recursive_envelope --include-ignored` | 5 passed |
| lens differential (`LENS_GPU_REQUIRE=metal,webgpu`) / rspcs | 13 / 39 passed |
| joy `release/0.4` over this zheng: `cargo test --release --workspace` | 220 passed, 0 failed |
| joy `wrapped_execution --ignored` (e2e profile 6, Metal) | passed, 79 s, 10.1 GB |

## 5. what is left to 1 s

- **IVC step: 1.19 s on Metal** (target ≤ 1 s: missed by ~0.2 s). Floor
  of this design at the current hemera kernel ≈ 0.75 s device + the
  serial CPU between them. Next: JIT-compiled zerocheck program on the
  device (the interpreter's round 0 is ~5× its arithmetic), the
  circuit build (72 ms, serial) and the accumulation eq tables
  (123 ms) on the device, overlap of CPU and device work across steps
  of a long run.
- **Wrap chain: 23.7 s on Metal** (target ≤ 5 s: missed by ~5×). It is
  hemera-bound: ≈ 1 G permutations at 35–40 M/s; the final level alone
  ≈ 500 M (its 1/512 codewords and the grinding the 64 KiB gate
  requires). No parameter change measured here gets below ~20 s: the
  chain shape is pinned by circuit sizes (§2). Reaching seconds needs a
  faster hemera kernel (the partial rounds' inversions are 60 % of a
  permutation; batching inversions across states was measured earlier
  without gain) or a smaller final circuit / a different final-level
  commitment.
- Keys: derivation stays once per chain (0.3 + 0.9 + 3.2 + 0.2 s on
  Metal); loading committed prover keys from disk is not built.
- WebGPU: the chain is 57 s (Metal 24 s): its permutation kernel is
  half Metal's (`gpu_bench` 10 vs 19 M/s with copies).
