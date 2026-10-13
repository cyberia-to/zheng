---
tags: zheng, audit
---
# Zheng audits

Source reviews and validation evidence live here. Protocol contracts are
defined in [specs](../specs/README.md).

- [Direct execution review](direct-execution-review.md) — soundness findings, obligations and implemented checks.
- [Public execution validation](public-execution.md) — tested relation, adversarial checks, CLI measurements and remaining gates.
- [zk profile, state binding and verifying keys, 2026-10](zk-profile-2026-10.md) — veil (succinct zk) against MPC-in-the-head, state evidence inside zheng, cached keys; raw numbers.
- [Accumulation and the nox machine, 2026-10](accumulation-2026-10.md) — phase 3: step relation, accumulation, measurements against the gates, what is not done.
- [Recursion (IVC over the nox machine), 2026-10](recursion-2026-10.md) — the step relation verifies the previous step in-circuit: constant 282–285 KB from 33 cycles to 1.57M cycles, bit-flip scan, gaps to 64 KB / 1 ms.
- [Wrap steps, 2026-10](wrap-2026-10.md) — the final verifier proved by three wrap levels: 62.5–62.9 KB from 33 to 1.57M cycles (≤ 64 KB met), verify 12–15 ms (≤ 1 ms missed), bit-flip scan 0 accepted.
- [Recursion adversarial review, 2026-10](recursion-review-2026-10.md) — PR #53 attacked: one hole (an extension value in a base slot unbound the final state from the last public input; fixed), circuit cell scan, live flag, binding, deferred claims, ledger recomputed.
- [Wrap adversarial review, 2026-10](wrap-review-2026-10.md) — PR #56 attacked: no soundness hole; a wrap key bound to its recursive proof and final-mode keys kept out of circuits (hardening, fixed); linear wiring pins every cell the memory argument pins; native-refused values break both modes; 546 single-message tampers refused; interactive weakest round 98.02 bits stated.
- [Wrap prover memory and verifier time, 2026-10](wrap-fastverify-2026-10.md) — PR #58: streamed codewords, key words once per key, chain `4i:16,8i,9f:24`, 63.9 KB final proof, verify 5.3–5.7 ms one thread, chain prove 83 s in 19.5 GB.
- [Wrap fast verifier adversarial review, 2026-10](wrap-fastverify-review-2026-10.md) — PR #58 attacked: no accepting attack; message digests made length-binding (transcript change), field-native closing kept from circuits, loaded keys' columns checked against their graph; ledger recomputed independently; concurrent verifiers deterministic.
