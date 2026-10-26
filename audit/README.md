---
tags: zheng, audit
---
# Zheng audits

Source reviews and validation evidence live here. Protocol contracts are
defined in [specs](../specs/README.md).

- [Direct execution review](direct-execution-review.md) — soundness findings, obligations and implemented checks.
- [Public execution validation](public-execution.md) — tested relation, adversarial checks, CLI measurements and remaining gates.
- [Node dependency profile, 2026-09-23](node-dependency-profile-2026-09-23.md) — historical: the Lens 0.2 / Nox 0.3 dependency closure of the 2026-09 node candidate (zheng#32, folded into #33); evidence as written.
- [zk profile, state binding and verifying keys, 2026-10](zk-profile-2026-10.md) — veil (succinct zk) against MPC-in-the-head, state evidence inside zheng, cached keys; raw numbers.
- [Accumulation and the nox machine, 2026-10](accumulation-2026-10.md) — phase 3: step relation, accumulation, measurements against the gates, what is not done.
- [Recursion (IVC over the nox machine), 2026-10](recursion-2026-10.md) — the step relation verifies the previous step in-circuit: constant 282–285 KB from 33 cycles to 1.57M cycles, bit-flip scan, gaps to 64 KB / 1 ms.
- [Wrap steps, 2026-10](wrap-2026-10.md) — the final verifier proved by three wrap levels: 62.5–62.9 KB from 33 to 1.57M cycles (≤ 64 KB met), verify 12–15 ms (≤ 1 ms missed), bit-flip scan 0 accepted.
- [Recursive envelope (profile 5), 2026-10](recursive-envelope-2026-10.md) — IVC proofs in `ZHENGPF1`: wire, rejection tests, profiles 1/4/5 on hash.tri and merkle-32.
- [Wrapped envelope (profile 6) and key layouts, 2026-10](wrapped-envelope-2026-10.md) — final proofs in `ZHENGPF1`: 62,962 B on hash.tri; pinned inner roots and key bundles (cold key cost 3 min / 30.9 GB → ~2 s → ~0.3 s); profiles 1/5/6 measured.
- [Recursion adversarial review, 2026-10](recursion-review-2026-10.md) — PR #53 attacked: one hole (an extension value in a base slot unbound the final state from the last public input; fixed), circuit cell scan, live flag, binding, deferred claims, ledger recomputed.
- [Wrap adversarial review, 2026-10](wrap-review-2026-10.md) — PR #56 attacked: no soundness hole; a wrap key bound to its recursive proof and final-mode keys kept out of circuits (hardening, fixed); linear wiring pins every cell the memory argument pins; native-refused values break both modes; 546 single-message tampers refused; interactive weakest round 98.02 bits stated.
- [Wrap prover memory and verifier time, 2026-10](wrap-fastverify-2026-10.md) — PR #58: streamed codewords, key words once per key, chain `4i:16,8i,9f:24`, 63.9 KB final proof, verify 5.3–5.7 ms one thread, chain prove 83 s in 19.5 GB.
- [Wrap fast verifier adversarial review, 2026-10](wrap-fastverify-review-2026-10.md) — PR #58 attacked: no accepting attack; message digests made length-binding (transcript change), field-native closing kept from circuits, loaded keys' columns checked against their graph; ledger recomputed independently; concurrent verifiers deterministic.
- [IVC step and wrap chain speed, with its review, 2026-10-14](ivc-speed-2026-10.md) — held words in one device pass, 4-ary IVC trees, profile 6's IVC at 1/8, rebalanced WHIR grinding: IVC step 3.45 → 1.19 s, wrap chain 41 → 24 s on Metal, same bytes on every backend; review: 4-ary path attacks, ledger recomputed, bit flips 0 accepted.
- [IVC step and wrap chain speed, round 2, 2026-10-14](ivc-speed-2-2026-10.md) — hemera kernels with batched partial inversions (Metal 1.44×, WebGPU grind 1.61×), key trees on disk, overlapped column assembly; compiled zerocheck programs measured and rejected: wrap chain 23.7 → 18.9 s on Metal, whole profile-6 process 31 → 22 s, same bytes.
- [Proof stack adversarial review, 2026-10](proof-stack-review-2026-10.md) — PRs #60/#61 attacked: no accepting attack; the profile-5 verifier's IVC key root (committed on the prover backend) now pinned — fail closed under a faulty device (fixed); split-key limbs bound to the committed words; program digest refused at every level; GPU verdicts equal (0 verifier backend calls); inner-level interactive figures corrected (108.92 / 102.35); 64,213 B recomputed.
- [The wrap chain's frontier under hemera 0.4, 2026-10-26](wrap-frontier-hemera-0.4-2026-10-26.md) — 972 chains planned on the build service with λ ≥ 128 fixed: the shipped chain bounds at 74,525 B (measured 72,957 B, final level 3,089 s on 4 threads); 8 chains bound ≤ 64 KiB, all fold 5 with final grinding ≥ 32 bits (`10f:32:5` 64,129 B, `9f:36:5` 64,937 B, best `10f:40:5` 59,537 B); their prover time is measured in round 3.
- [veil prover coins, 2026-10-14](veil-coins-2026-10.md) — counter-mode PRF over hemera `permute_ct` with labelled streams, parallel fills and row-parallel encoding: veil prove 1.8–2.1× faster (merkle-32 2.20 → 1.19 s on Metal), same bytes; PRF bound and HVZK argument; proof-size levers measured and estimated; bit flips 0 accepted.
- [fast path 2, 2026-10-14](fast-path-2-2026-10.md) — hemera node jet (one permutation per Merkle level: depth 32 1.02 s → 0.15 s cold on Metal, 63.6 → 46.7 KB, 16 grinding bits), veil held key + counter-mode coins (mudra P1 depth 20/32: 965/1,342 → 255/396 ms), Metal shader archive, public proof readers; self-review, bit flips 0 accepted.
