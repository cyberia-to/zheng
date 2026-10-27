---
tags: zheng, roadmap
---
# zheng roadmap

what is built is specified in [specs](../specs/README.md) and measured in [audit](../audit/README.md). this page holds the two things that are not: the status of the repair, phase by phase, and the open proposals. the design record is [[soft3/proposals/proof-system-repair|proof-system repair]]; its gates are fixtures and commands, so a phase below is closed only when its gate is green.

## status of the repair (master, 2026-10-27)

the crate is 0.4.0 on master, not published (crates.io stops at 0.3.1, the retired fold). every figure below was measured on hemera 0.3.1, which the crate still pins; the frozen material is hemera 0.4, and moving zheng to it is the in-flight sweep below.

| phase (§5) | what | in master | open |
|---|---|---|---|
| 0 | relation shrink: linear forms, native constants, degree-7 S-box | done (zheng#45): hash.tri certificate 294,861 → 15,608 B (`audit/compact-relation-2026-10-09.md`) | — |
| 1 | soundness floor | public prefix and pinned constant placed by the verifier, `vk` digest absorbed, Fp3 challenges, one envelope `ZHENGPF1` with a profile byte, the [[soundness]] ledger; fixtures `forged-io`, `forged-program`, `zeroed-constant`, `meaningless-witness` rejected (`rs/tests/attack_fixtures.rs`) | the ledger still has conjectured rows (relation compiler, hash, IVC and wrap composition, program binding by digest), so the "no conjectured row" gate is not passed |
| 2 | PCS bake-off | WHIR ships in the succinct profile (envelope profile 1); TensorRs lost and stays decodable until phase 5 (`audit/succinct-profile-2026-10.md`); bit-flip scans 0 accepted | small class: hash.tri 16,756 B meets the ≤ 20 KB gate, misses the ≤ 16 KB stretch; verify ≤ 1 ms missed (< 10 ms, soft3 `audit/proof-latency-2026-10.md`); large class: 71,081 B at 2^20, over 64 KB |
| 2h | the hash row | decided outside zheng: hemera 0.4 (hemera#15) frozen 2026-10-16, under the public cryptanalysis campaign | zheng's gadgets, machine and fixtures still implement hemera 0.3.1: the sweep is #69/#73 below |
| 3 | uniform step relation, accumulation, IVC | the nox machine as one step relation (profile 4), hash-based accumulation of RS claims and its decider, IVC (profile 5), the wrap chain (profile 6): final proof ≤ 64,213 B over every transcript, 512 statements decided in one proof (`accumulate::ccs`) | verify ≤ 1 ms missed (wrap final proof 5.3–5.7 ms on one thread, `audit/wrap-fastverify-2026-10.md`); the Trident second verifier (`verify(verify(π))` across Rust and Trident) does not exist; on hemera 0.4 the 64 KiB bound is the L3b decision below |
| 4 | `zk` profile | veil (profile 2 scheme 2): 63.9 KB for one hash of a secret preimage, honest-verifier statistical zero knowledge in the ROM; MPC-in-the-head (scheme 1) as fallback | a smaller zk opening (veil-W, #67) is research |
| P | the prover everywhere | lens backend trait with Metal and WebGPU backends and the CPU fallback, same bytes on every backend; profile 1 product statements ≤ 1 s on Metal up to Merkle depth 16 (soft3 `audit/proof-latency-2026-10.md`) | profile 6 is a ~19 s wrap chain on Metal (`audit/ivc-speed-2-2026-10.md`), not seconds-class; no phone measured |
| 5 | delete | — | the `legacy` feature (the 0.3 fold, universal CCS, φ* SpMV, the `zheng` CLI), TensorRs decoding and legacy formats are still in the tree |

## in flight

| PR | what | state |
|---|---|---|
| #69, #73 | zheng on hemera 0.4: gadgets, node jet, machine and circuit layouts, goldens re-pinned; #73 is #69 under a CI stand (train row L3) | draft; one failing test, the 64 KiB final-proof bound, which waits for L3b |
| #78, #79 | L3b, the owner's decision (due 2026-10-29 12:00 UTC): keep the 64 KiB gate with final level `10f:32:5` (#78), or raise it to 72 KiB with `9f:26:5` (#79) | draft, stacked on #73 |
| #77 | `[profile.dev] opt-level = 3`, so `cargo test` fits the train's stack-zheng gate (G10b) | the change is already on master (taken with the promotion); the PR stays open only as part of the #73 stack |
| #67 | veil-W (gate G1 of soft3 `proposals/privacy-frozen.md`): masked Spartan with a zero-knowledge WHIR opening, SPEND in ~46.5 KB, measured on hemera 0.3 | draft, research; needs an independent review and a re-measure on hemera 0.4 |
| #70 | block aggregation (gate G2): one proof per block | draft, in flight |

## proposals

| proposal | status | target |
|---|---|---|
| [[gpu-prover]] | draft — the backends exist (Metal, WebGPU, CPU); the device-resident pipeline does not | one pipeline from trace to proof without CPU phases |
| [[ring-aware-fhe]] | draft — the ring PCS is specified in lens ([[ring-pcs]]); zheng has no ring-structured CCS or FHE jets | TFHE bootstrapping as ring-structured CCS and dedicated jets |
| [[gravity-commitment]] | draft — to be restated and measured on the shipped RS/WHIR commitment | mass-weighted polynomial encoding: hot positions open cheaper |

the recursive-Brakedown opening (a constant-size opening that skipped the Merkle authentication of its queries) is not a proposal: it is unsound in a hash-only world and no version brings it back; its record is [[recursive-brakedown]] in docs/explanation.

## lifecycle

| status | meaning |
|---|---|
| in reference | specified in specs/ and implemented |
| accepted | approved, ready to implement |
| draft | idea captured, open for discussion |
