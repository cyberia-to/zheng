---
tags: zheng, audit, release, consistency
crystal-type: report
crystal-domain: comp
date: 2026-10-27
runs: 2026-10-29
---
# consistency of master with the proof-system repair — 2026-10-27

the owner's order (2026-10-27): promote `release/0.4` into `master`, sweep every file of the repository against the repair scheme (soft3 `proposals/proof-system-repair.md`, soft3 `proposals/privacy-frozen.md` §1), and check the result three times. this page is the ground truth the sweep was held to and the record of the three runs.

## 1. the promotion

`master` 513f1c5 (crate 0.3.3, 14 commits of its own) merged with `release/0.4` 0ad4c3e (crate 0.4.0, 246 commits ahead) in 5ffd5f1. kept from master: AGENTS.md as the single instruction file (no CLAUDE.md), the zippel docs and `specs/proto`, the tade dependency. conflicts in docs and specs were resolved toward release/0.4's rewritten pages; Cargo files toward release/0.4. commits on top of the merge:

| commit | what |
|---|---|
| 2633f34 | root workspace `exclude = [".worktrees"]` (a task checkout under `zheng/.worktrees/` otherwise took the canonical root as the workspace of every sibling); `Cargo.lock` takes the stand's `cyber-lens-gpu` 0.1.1 |
| 5a14ae1 | `cargo fmt` over rs and cli (the pass zheng#74 ran on the hemera 0.4 sweep) |
| e3b21b4 | clippy clean on every target and feature with `-D warnings` (carries c24ba05 of zheng#74 plus the legacy, test and example lints it did not reach) |
| 78f6d94 | dev profile at opt-level 3 (the change of zheng#77, G10b) |
| 58e417a | CLI: the tape → tade rename finished (08844d5, 6bfbe48 of the sweep); help names the legacy API |
| a076137 | crate keywords name WHIR; the v1 challenge rule named by its rule |

the documentation sweep follows these in its own commits. no code changed after a076137.

## 2. the stand

zheng resolves its siblings by path (`../../<repo>`). master pins hemera 0.3, and the tips of nox `release/0.4` and lens `release/0.2` already require hemera 0.4, so master builds only at these revisions (README.md § build):

| sibling | revision | crate |
|---|---|---|
| strata | 5ef0c84 (`main`) | `strata-nebu` 0.1.1 |
| hemera | fd55f99 (`main`) | `cyber-hemera` 0.3.1 |
| nox | 12adaf8 (`release/0.4`, before nox#31) | `cyber-nox` 0.3.0 |
| lens | b1040c2 (`release/0.2`, before lens#37) | `cyber-lens` 0.2.0, `cyber-lens-gpu` 0.1.1 |
| tade | 778dc6f (`main`) | `tade` 0.1.0 |
| honeycrisp | 595ce26 (`main`) | `aruminium` 0.2.0 |

toolchain: cargo/rustc 1.99.1 (Homebrew), Apple M4 Max (12P + 4E, 40-core GPU, 48 GB), macOS 26.4. the machine was shared with other agents (load averages are given per run).

## 3. ground truth

each claim of the repair scheme, where the repository states it, where the code implements it, what was measured, and the verdict. "measured" names its command; every command ran on code revision a076137 unless an audit is named.

| claim | where stated | where implemented | measured | verdict |
|---|---|---|---|---|
| one field: Goldilocks committed, Fp3 for every challenge | README, specs/README, specs/transcript | `field::ChallengeField`, `Transcript::squeeze_fp3`; sumcheck and Spartan generic over the field | ledger row "transcript, extension challenge": p³ ≈ 2^192 | current |
| one hash: hemera | README, specs/README, specs/soundness (hash row) | `cyber-hemera` 0.3 in `rs/Cargo.toml` and `cli/Cargo.toml`, resolved to 0.3.1 in `Cargo.lock`; `machine/hemera.rs` `ROUNDS = 24`, inverse S-box in the partial rounds | — | current, hemera 0.3.1. the frozen material hemera 0.4 is not in master: draft sweep #69/#73, gated on L3b (#78 / #79). stated in README, AGENTS.md, specs/README, specs/soundness |
| one code: Reed–Solomon, opened by WHIR | README, specs/README, docs/explanation/polynomial-commitments | lens `rspcs` `Whir` (id 1) in `execution::succinct`; field-native WHIR in `recursion::whir`; TensorRs (id 2) decodable; veil's hiding RS tensor in `execution::veil::hiding` | profile 1 bits 128.04–128.08 with grinding (`fast_path`) | current. Brakedown only behind the `legacy` feature (and in bbg's `QueryProof`, outside zheng) |
| one IOP: Spartan over CCS + sumcheck | README, specs/superspartan, specs/sumcheck | `spartan::iop`, `spartan::reduce` (round degree fixed by the verifier in `decompress`) | — | current |
| the machine is an AIR proved by a sumcheck zerocheck | README, specs/README, specs/machine | `air::zerocheck`, `machine` | profile 4/5/6 rows below | current; the old line "no AIR" was false and is gone |
| one wire format with a profile byte | README, specs/execution | `envelope`: magic `ZHENGPF1`, version 1, profiles 0–6 | — | current |
| public prefix, pinned constant, verifier-derived relation | README, specs/verifier, specs/execution | `execution::relation`, `execution::certificate`, `execution::vk` | `rs/tests/attack_fixtures.rs`: forged io, forged program, zeroed constant, meaningless witness, truncated, wrong state root, wrong magic — all rejected (test run §4) | current |
| soundness ledger | specs/soundness | — | — | exists; conjectured rows remain (relation compiler tested not proven, hash, program digest, IVC and wrap composition), so the gate "no conjectured row in a production profile" (repair §6) is not passed |
| profile 0 public certificate v3 | specs/execution | `execution::certificate` | 6,463 B hash.tri (`audit/succinct-profile-2026-10.md`) | current; linear, witness disclosed |
| profile 1 succinct ≤ 20 KB small, ≤ 64 KB at 2^18 | README, specs/README | `succinct::prove_default` with `device_params` (rate 1/64, folding 4/5, grinding 16/22/24) | `fast_path`: hash.tri 16,791 B, verify 4.9 ms; merkle-16 60,077 B; merkle-32 63,594 B | ≤ 20 KB small gate met (16,791 B); ≤ 16 KB stretch missed; ≤ 64 KB met to 2^18; verify ≤ 1 ms missed |
| profile 2 zk (veil; MITH fallback) | README, specs/execution, specs/native-private-ccs | `execution::veil`, `execution::zk` | 63.9 KB hash of a secret preimage (`audit/zk-profile-2026-10.md`); not re-measured (masked bytes vary) | current; honest-verifier statistical zk in the ROM |
| profile 3 state-public v3 | specs/execution | `execution::state`, `execution::state_evidence` | — | current |
| profile 4 machine (accumulation, ARC/WARP-style) | README, specs/accumulation, specs/machine | `machine`, `accumulate` | `envelope_profiles`: hash.tri 96,083 B, verify 5.0 ms | current; grows with segments |
| profile 5 IVC, constant in steps | README, specs/recursion | `recursion::ivc`, `envelope::recursive` | `envelope_profiles`: hash.tri 407,947 B (rate 1/16, 4-ary trees), verify 9.5 ms | current; constant, above 64 KB |
| profile 6 wrapped, ≤ 64 KB for any computation | README, specs/recursion, specs/README | `recursion::wrap`, `envelope::wrapped` | `envelope_profiles`: hash.tri 62,687 B, verify 5.4 ms, prove 66.8 s CPU with keys, 12.1 GB; bound 64,213 B over every transcript (`wrap::tests::the_shipped_final_proof_is_at_most_64_kib_over_every_transcript`) | size and constancy goals met; verify ≤ 1 ms missed |
| prover everywhere, same bytes on every backend | specs/README, roadmap/gpu-prover | lens `cyber-lens-gpu` (Metal through honeycrisp, WebGPU), CPU | `fast_path` CPU and Metal: identical envelope sizes; byte identity across backends in soft3 `audit/proof-latency-2026-10.md` | current |
| user-device proofs ≤ 1 s on Metal | roadmap/README | profile 1 | `fast_path` Metal: hash.tri 19 ms, merkle-16 409 ms, merkle-32 827 ms (prove, in-process) | met to depth 32 in-process on this run; cold process figures in soft3 `audit/proof-latency-2026-10.md` |
| second verifier in Trident | roadmap/README, docs/explanation/recursion | — | — | roadmap (not in zheng) |
| phase 5 deletion (`folding`, `ccs`, `phi`, Brakedown wire, legacy formats) | roadmap/README, README | still present behind `legacy` | — | open; the CLI drives only this path |
| no stale claims (repair §C) | — | — | soft3 `scripts/stale-proof-claims.nu` over the tree: run (c) | see §4 |
| crate published | README, CHANGELOG | — | crates.io `zheng` max version 0.3.1 | 0.4.0 unpublished; 0.3.2 and 0.3.3 never published |

## 4. the three runs

three runs, 2026-10-29, each from fresh clones of origin/master at c54a5a7 (the promotion merge 4068e9c, #80, plus one docs commit; code identical to a076137), on the stand of §2. the first attempt of 2026-10-27 at 4068e9c was cut off by an API outage (run 1 stalled in `fast_path` and was stopped by its time limit) and is not counted; its completed steps agreed with the runs below.

### 4.1 run (a): build, test, clippy, the README's commands

`python3 audit/tools/consistency_run.py <n> <zheng-repo>` executes README.md § build of origin/master verbatim: `mkdir`, seven `git clone`s, six `git -C … checkout <rev>`, then from `zheng/`:

```
cargo build --release --locked
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets --features zheng/legacy,zheng/serde,zheng/test-hooks,zheng-cli/legacy -- -D warnings
cargo run --release --locked -p zheng --example fast_path -- hash.tri merkle-16 merkle-32
ZHENG_PROFILES=1,4,5,6 cargo run --release --locked -p zheng --example envelope_profiles -- hash.tri
```

(the last with `ZHENG_ENVELOPE_DIR` added to keep the envelopes). every command exited 0 in every run; no clone was left modified (`Cargo.lock` unchanged under `--locked`).

| run | start → end (UTC) | load 1-min at start → end | build | test | clippy | fast_path | envelope_profiles | tests passed / failed / ignored |
|---|---|---|---|---|---|---|---|---|
| 1 | 12:48:03 → 13:09:22 | 7.0 → 80.6 | 8.7 s | 816.4 s | 11.6 s | 41.0 s | 170.9 s | 394 / 0 / 19 (28 binaries) |
| 2 | 13:09:27 → 13:25:05 | 74.6 → 66.1 | 7.3 s | 588.4 s | 9.4 s | 26.1 s | 108.3 s | 394 / 0 / 19 |
| 3 | 13:25:08 → 13:39:27 | 61.6 → 46.0 | 7.0 s | 529.0 s | 9.3 s | 26.5 s | 86.0 s | 394 / 0 / 19 |

clippy reported no warning of zheng or zheng-cli (the only warnings are cyber-hemera's manifest lint name and the `block` crate's future-incompatibility note, both outside this repository).

measurements, CPU backend (the machine was shared; load as above, so times vary ±60 % between runs and are upper bounds; sizes are deterministic):

| profile · fixture | envelope | run 1 prove / verify | run 2 | run 3 |
|---|---|---|---|---|
| 1 · hash.tri | 16,791 B | 43.4 ms / 5.70 ms | 40.2 / 5.08 | 41.3 / 5.02 |
| 1 · merkle-16 | 60,077 B | 1,110.6 ms / 198.2 ms | 667.8 / 164.0 | 643.5 / 159.1 |
| 1 · merkle-32 | 63,594 B | 2,326.1 ms / 399.2 ms | 1,391.4 / 307.2 | 1,368.0 / 312.0 |
| 4 · hash.tri | 96,083 B | 13.8 s / 8.49 ms | 8.4 s / 6.73 | 7.5 s / 5.15 |
| 5 · hash.tri | 407,947 B | 20.1 s / 15.74 ms | 14.1 s / 11.90 | 10.7 s / 9.61 |
| 6 · hash.tri | 62,687 B | 135.9 s / 10.39 ms | 84.7 s / 7.47 | 66.9 s / 5.53 |

(profile 1 verify from `fast_path`; profiles 4–6 verify = decode + verify median of 5 from `envelope_profiles`.) bits for profile 1: 128.08 / 128.08 / 128.04 with grinding, 112.08 / 112.08 / 106.04 without, in every run.

determinism: the four envelopes are byte-identical across the three runs and equal to the measurement of 2026-10-27 at a076137 (§3):

| envelope | SHA-256 (runs 1, 2, 3 and 2026-10-27) |
|---|---|
| hash.tri.p1.zheng | f3fd3651303217c31930aaf4d0abdcc6677508cfd4fe48372555d426508ae44e |
| hash.tri.p4.zheng | f87d55ef08bc5daf6f3bac9b9c162279a63ca5c382668f38bd20cf6076611671 |
| hash.tri.p5.zheng | 9e8348ebd3dcadc69066e09b43ae554869d3daf8631621cceb420851ce7dce32 |
| hash.tri.p6.zheng | 5c989d51f432d4dac82b9c5d6178e6d51dc4b0dca12dc053c2b885c0ab7d616b |

### 4.2 run (b): links

`python3 audit/tools/links.py <zheng-checkout> --graph <the directory holding the sibling repos>` over each run's clone (graph `~/cyber`): relative links must resolve inside the checkout; wiki-links must name a page of the checkout or of a sibling repository that exists (a repo, a path, a page name or a frontmatter alias). result in all three clones: 663 links, 0 unresolved. during the sweep (2026-10-27) the forks unlinked 45 wiki-links to pages that exist nowhere in the graph and fixed the rest.

### 4.3 run (c): stale and banned terms

- soft3 `scripts/stale-proof-claims.nu --root <dir holding only the clone>` (soft3 at its 2026-10-29 checkout): `0 hits — the ledger is closed`, all three clones. before the sweep the merged tree had 22 hits in 6 files.
- `sh audit/tools/terms.sh <zheng-checkout>` (identical counts in all three clones at c54a5a7; this page, which quotes the terms, adds its own hits from the commit that records the runs), each remaining hit read and kept for the reason given:

| term | hits | why they stay |
|---|---|---|
| STARK | 41 | other systems (Stwo, Triton, RISC Zero, Trisha), page titles and aliases, and sentences saying zheng proofs are not STARKs; none names zheng a STARK |
| Brakedown | 155 | the `legacy` feature, history, bbg's table digest, dated audits, the CHANGELOG |
| "2 KB" | 10 | substrings of other figures (52 KB, 12 KB, 62 KB …); no 2 KB claim |
| "2 KiB" | 3 | substrings of "72 KiB" (the L3b option) |
| "100 ns" | 0 | — |
| sub-millisecond | 2 | two audit receipts stating such claims are absent |
| 0.3.3 | 4 | CHANGELOG history and this page |
| CLAUDE.md | 1 | this page (the file is gone; AGENTS.md is the only instruction file) |
| `[[tape]]`, `tape::` | 0 | — |
| release/0.4 | 30 | dated audits' stands, the CHANGELOG and README naming the promotion, the sibling table (nox `release/0.4`), a trident URL |
| the 0.3 fold scheme's name | 1 | CHANGELOG history (allow-listed by the stale gate) |
| the retired opening's claim to need no authentication paths | 0 | — |
| "no AIR" | 1 | this page, quoting the removed sentence |


## 5. pull requests and branches

merged: #80 (`promote/release-0.4-into-master` → `master`, merge 4068e9c, 2026-10-27), then c54a5a7 (docs) and this page's record pushed to master directly by the owner's authorization; `release/0.4` fast-forwarded to master each time (no divergence).

closed on 2026-10-27, each with a note naming what superseded it (branches kept: not contained in master):

| PR | what it was | superseded by |
|---|---|---|
| #20 `launch/5-fold-order-independence` | fold either order (`folding/decide.rs`) | the legacy fold is behind `legacy` and goes in phase 5; accumulation replaced it |
| #21 `launch/10-p1-signal-content-leak` | audit: the signal wire names the author | soft3 `proposals/privacy-frozen.md` §1.6 (speaking is spending); the finding is about cybergraph/foculus, not zheng |
| #22 `launch/scan-zheng-clean-build` | clean build; TensorMerkle gap | README § build (pinned stand), the `.worktrees` exclude, these three runs; TensorMerkle is legacy |
| #26 `launch/89-fold-root-replay-assert` | legacy look-opening replay | `ccs` is legacy; reads are authenticated by `execution::state_evidence` |
| #29 `launch/150-phi-star-graph-commit-binding` | φ* graph commit binding | φ* SpMV is legacy; no shipped profile proves φ* |
| #34 `launch/40-sumcheck-degree-check` | round-polynomial degree check | the shipped verifiers read compressed rounds through `spartan::reduce::decompress`, which fixes each round's degree from the verifier's own instance; the patched `SpartanVerifier` serves only retired paths |
| #44 `docs/proving-link` | phi-spmv links `tru/specs/proving.md` | the target does not exist on tru master; phi-spmv is a legacy page |

open, in flight (status comment posted on each on 2026-10-27; all are drafts; bases `release/0.4` = master, or the sweep branch):

| PR | status | what it needs |
|---|---|---|
| #69 | zheng on hemera 0.4, the dependents sweep (one commit, never built alone) | carried by #73 |
| #73 | #69 under a CI stand (train row L3): builds, one failing test (the 64 KiB final-proof bound under hemera 0.4) | the owner's L3b decision, then a merge of master (mechanical except `machine/layout.rs`) |
| #78 / #79 | L3b: keep the 64 KiB gate with final level `10f:32:5` (#78) or raise it to 72 KiB with `9f:26:5` (#79) | the owner's decision; due 2026-10-29 12:00 UTC per #77, not recorded on either PR at 13:40 UTC |
| #77 | dev profile opt-level 3 (G10b) | already on master (78f6d94); redundant once #73 merges master |
| #67 | veil-W (G1): zk profile with a WHIR opening, SPEND ~46.5 KB, measured on hemera 0.3 | independent review, re-measure on hemera 0.4 |
| #70 | block aggregation (G2): one proof per block | in flight |

remote branches: deleted 2026-10-27 because fully contained in master — `chore/0.2.0`, `docs/l5a-carry`, `docs/universal-step-ccs-plan`, `feat/axis-openings`, `feat/hash-openings`, `feat/look-root`, `feat/proof-serde`, `feat/universal-step-ccs`, `fix/fold-step-witness-gate`, `fix/group-by-structure`, `fix/tade-path`, `fix/unchecked-wire-bytes`, `fix/witness-off-the-wire`, `promote/release-0.4-into-master`. kept (not contained): the heads of the open PRs and the sweep stack (`ci/hemera-0.4-sweep`, `feat/hemera-0.4`, `feat/zk-small`, `feat/block-aggregate`, `fix/g10b-dev-profile`, `l3b/option-i-64kib`, `l3b/option-ii-raised-gate`, `l3b/common`, `fix/l3a-hygiene`, `fix/g10b-test-profile`, `chore/l5a-tade-rename`), CI diagnostics (`diag/g10b-no-fail-fast`, `diag/l3-sweep-failures`, `diag/l3-sweep-fix`, `diag/l3b-frontier`, `diag/l3b-frontier-2`, `diag/l3b-options`, `diag/l5a-76-cli`), the closed PRs' heads and the unPRed September `launch/*` asserts (`launch/184-…`, `233-…`, `80-…`, `84-…`, `85-…`, `93-…`, `99-…`, all against the legacy path), `fix/warrior-release`, `docs/proving-link`.

## 6. what is still red

- hemera 0.4, the frozen material, is not in master (#69/#73); one test fails under it until the L3b decision (#78 / #79).
- verify ≤ 1 ms: no profile meets it (profile 1 5.0–5.7 ms at hash.tri, profile 6 5.5–10.4 ms in the runs of §4).
- the L3b decision (#78 / #79) was due 2026-10-29 12:00 UTC and is not recorded on the PRs.
- conjectured ledger rows keep the repair's release gate shut.
- phase 5 (deletion of the legacy path) and the Trident second verifier are not done.
- master builds only against pinned sibling revisions on release lines (§2); it rejoins the siblings' tips with the hemera 0.4 sweep.
