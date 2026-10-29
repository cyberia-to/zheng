---
tags: zheng, audit
---
# zheng audits

Source reviews, measurements and validation receipts. Protocol contracts are
defined in [specs](../specs/README.md); the status of the repair, phase by
phase, is in [roadmap](../roadmap/README.md). Every page is a dated record:
its stand, commands and numbers are kept as written. Unless a page says
otherwise, it was measured on hemera 0.3.1 — the version the crate still
pins; the frozen material is hemera 0.4 (sweep zheng#69/#73), and several
pages carry a note saying which of their hemera figures that moves.

## the promotion of 2026-10-27

- [Consistency receipt, 2026-10-27](consistency-2026-10-27.md) — the 2026-10-27 promotion of release/0.4 into master: ground truth, three runs.

## the proof-system repair, 2026-10 (soft3 `proposals/proof-system-repair.md`)

phase 0 and 2 — relation and the succinct profile:

- [Compact public execution relation, 2026-10-09](compact-relation-2026-10-09.md) — phase 0: linear forms, native constants, the degree-7 S-box row; hash.tri certificate 294,861 → 15,608 B.
- [Succinct profile and PCS bake-off, 2026-10-09](succinct-profile-2026-10.md) — profile 1: Spartan over Fp3 + one lens opening; WHIR against TensorRs, WHIR ships; sizes, verify times, bit-flip scans.
- [zk profile, state binding and verifying keys, 2026-10](zk-profile-2026-10.md) — veil (succinct zk) against MPC-in-the-head, state evidence inside zheng, cached keys; raw numbers.
- [veil prover coins, 2026-10-14](veil-coins-2026-10.md) — counter-mode PRF over hemera `permute_ct` with labelled streams, parallel fills and row-parallel encoding: veil prove 1.8–2.1× faster (merkle-32 2.20 → 1.19 s on Metal), same bytes; PRF bound and HVZK argument; proof-size levers measured and estimated; bit flips 0 accepted.

phase 3 — the machine, accumulation, recursion and wrap:

- [Accumulation and the nox machine, 2026-10](accumulation-2026-10.md) — phase 3: step relation, accumulation, measurements against the gates, what is not done.
- [The nox machine — every opcode, 2026-10-09](machine-opcodes-2026-10.md) — zheng#52: lt, word ops, call, look and 63-level axis addresses get traces; coverage of the machine relation.
- [Recursion (IVC over the nox machine), 2026-10](recursion-2026-10.md) — the step relation verifies the previous step in-circuit: constant 282–285 KB from 33 cycles to 1.57M cycles, bit-flip scan, gaps to 64 KB / 1 ms.
- [Recursion adversarial review, 2026-10](recursion-review-2026-10.md) — PR #53 attacked: one hole (an extension value in a base slot unbound the final state from the last public input; fixed), circuit cell scan, live flag, binding, deferred claims, ledger recomputed.
- [Wrap steps, 2026-10](wrap-2026-10.md) — the final verifier proved by three wrap levels: 62.5–62.9 KB from 33 to 1.57M cycles (≤ 64 KB met), verify 12–15 ms (≤ 1 ms missed), bit-flip scan 0 accepted.
- [Wrap adversarial review, 2026-10](wrap-review-2026-10.md) — PR #56 attacked: no soundness hole; a wrap key bound to its recursive proof and final-mode keys kept out of circuits (hardening, fixed); linear wiring pins every cell the memory argument pins; native-refused values break both modes; 546 single-message tampers refused; interactive weakest round 98.02 bits stated.
- [Wrap prover memory and verifier time, 2026-10](wrap-fastverify-2026-10.md) — PR #58: streamed codewords, key words once per key, chain `4i:16,8i,9f:24`, 63.9 KB final proof, verify 5.3–5.7 ms one thread, chain prove 83 s in 19.5 GB.
- [Wrap fast verifier adversarial review, 2026-10](wrap-fastverify-review-2026-10.md) — PR #58 attacked: no accepting attack; message digests made length-binding (transcript change), field-native closing kept from circuits, loaded keys' columns checked against their graph; ledger recomputed independently; concurrent verifiers deterministic.
- [Recursive envelope (profile 5), 2026-10](recursive-envelope-2026-10.md) — IVC proofs in `ZHENGPF1`: wire, rejection tests, profiles 1/4/5 on hash.tri and merkle-32.
- [Wrapped envelope (profile 6) and key layouts, 2026-10](wrapped-envelope-2026-10.md) — final proofs in `ZHENGPF1`: 62,962 B on hash.tri; pinned inner roots and key bundles (cold key cost 3 min / 30.9 GB → ~2 s → ~0.3 s); profiles 1/5/6 measured.
- [Proof stack adversarial review, 2026-10](proof-stack-review-2026-10.md) — PRs #60/#61 attacked: no accepting attack; the profile-5 verifier's IVC key root (committed on the prover backend) now pinned — fail closed under a faulty device (fixed); split-key limbs bound to the committed words; program digest refused at every level; GPU verdicts equal (0 verifier backend calls); inner-level interactive figures corrected (108.92 / 102.35); 64,213 B recomputed.

phase P — the prover on every device:

- [Prover profile and backends, 2026-10-10](prover-profile-2026-10.md) — where prove time goes; Metal and WebGPU backends through lens, the CPU fallback; the same proof bytes on every backend.
- [IVC step and wrap chain speed, with its review, 2026-10-14](ivc-speed-2026-10.md) — held words in one device pass, 4-ary IVC trees, profile 6's IVC at 1/8, rebalanced WHIR grinding: IVC step 3.45 → 1.19 s, wrap chain 41 → 24 s on Metal, same bytes on every backend; review: 4-ary path attacks, ledger recomputed, bit flips 0 accepted.
- [IVC step and wrap chain speed, round 2, 2026-10-14](ivc-speed-2-2026-10.md) — hemera kernels with batched partial inversions (Metal 1.44×, WebGPU grind 1.61×), key trees on disk, overlapped column assembly; compiled zerocheck programs measured and rejected: wrap chain 23.7 → 18.9 s on Metal, whole profile-6 process 31 → 22 s, same bytes.
- [fast path 2, 2026-10-14](fast-path-2-2026-10.md) — hemera node jet (one permutation per Merkle level: depth 32 1.02 s → 0.15 s cold on Metal, 63.6 → 46.7 KB, 16 grinding bits), veil held key + counter-mode coins (mudra P1 depth 20/32: 965/1,342 → 255/396 ms), Metal shader archive, public proof readers; self-review, bit flips 0 accepted.
- the user-device latency audit of 2026-10-14 (profile 1 ≤ 1 s on Metal up to Merkle depth 16) lives in soft3: `audit/proof-latency-2026-10.md`.

checking the IOP:

- [zheng's IOP through zippel, 2026-10-24](zippel-2026-10-24.md) — the Spartan IOP written as zippel protocols (`specs/proto/`): completeness PASS, a planted bug caught, transcript order matched.

## before the repair, 2026-09 — the public and private execution certificates

- [Direct execution review](direct-execution-review.md) — soundness findings, obligations and implemented checks.
- [Public execution validation](public-execution.md) — tested relation, adversarial checks, CLI measurements and remaining gates.
- [Private execution and state release requirements, 2026-09-11](private-execution-release.md) — historical: the Triton-backed private path through Trisha and Joy and what a full private release required then.
- [Experimental tagged relation validation, 2026-09-12](tagged-relation-validation.md) — the bounded tagged-relation kernel, tested locally; review and integration were left open.
- [General bounded nox relation review](general-nox-relation-review.md) — an architectural design review; its step-relation sketch is what phase 3 built.
- [Node dependency profile, 2026-09-23](node-dependency-profile-2026-09-23.md) — historical: the Lens 0.2 / Nox 0.3 dependency closure of the 2026-09 node candidate (zheng#32, folded into #33); evidence as written.
- [Native private proof review](soft3-reaudit/proof-review.md) — independent correctness and privacy review of the MPC-in-the-head backend (`execution::zk`), pinned revisions.

## receipts (directories)

- [native-private/](native-private/README.md) — native private CCS acceptance, 2026-09-27: backend and CLI installation, feature-branch evidence.
- [compact-noun-admission/](compact-noun-admission/README.md) — `Memory::append_value` admission of disclosed atoms and pairs; commands, logs, hashes.
- [disclosed-noun-memory/](disclosed-noun-memory/README.md) — the experimental disclosed noun-memory table; local development evidence.
- [disclosed-evaluation-dag/](disclosed-evaluation-dag/README.md) — the finite evaluation-DAG component; source and command receipts.
- [disclosed-semantic-stream/](disclosed-semantic-stream/README.md) — the bounded disclosed semantic stream integrating the two above.
- [noun-cost-component/](noun-cost-component/README.md) — the local noun/Cost CCS component of the tagged relation; full gate receipts.
- [legacy-wire-example-feature/](legacy-wire-example-feature/README.md) — the `legacy_wire_cost` example declares the feature it needs.

## tools

- `tools/joy_table.sh`, `tools/warm_table.sh` — `joy prove` / `joy verify` tables per backend (cold and warm), used by soft3 `audit/proof-latency-2026-10.md` and `fast-path-2-2026-10.md`.
- `tools/tree.py` — the main thread's call tree from macOS `sample` output.
- `tools/consistency_run.py`, `tools/links.py`, `tools/terms.sh` — the three runs of [consistency-2026-10-27.md](consistency-2026-10-27.md): a fresh stand running README § build verbatim, the link check, the banned-term sweep; each takes the repository as an argument.
- `ivc-speed/ledger.py` — independent recomputation of the rebalanced field-native WHIR ledgers, used by `ivc-speed-2026-10.md`.
