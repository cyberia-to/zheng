---
tags: zheng, audit, release, consistency
crystal-type: report
crystal-domain: comp
date: 2026-10-27
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

the runs check origin/master after the push; their record is the next commit of this page.

## 5. pull requests and branches

the triage of the open pull requests is recorded with the runs.

## 6. what is still red

- hemera 0.4, the frozen material, is not in master (#69/#73); one test fails under it until the L3b decision (#78 / #79).
- verify ≤ 1 ms: no profile meets it (profile 1 4.9 ms at hash.tri, profile 6 5.4 ms on this run).
- conjectured ledger rows keep the repair's release gate shut.
- phase 5 (deletion of the legacy path) and the Trident second verifier are not done.
- master builds only against pinned sibling revisions on release lines (§2); it rejoins the siblings' tips with the hemera 0.4 sweep.
