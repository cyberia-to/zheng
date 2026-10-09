---
tags: zheng, audit, machine, opcodes, phase 3
crystal-type: audit
crystal-domain: crypto
---
# the nox machine — every opcode, 2026-10-09

Branch `feat/machine-opcodes` (zheng #52, stacked on #51). Closes the
coverage item of `accumulation-2026-10.md` §7: lt, xor/and/not/shl, call,
look and axis addresses `≥ 2^32` now have traces. Contract:
`specs/machine.md`; ledger: `specs/soundness.md` (machine relation row).

Stand R2: zheng `feat/machine-opcodes`, joy `feat/accumulation` (639bcea),
bbg `feat/sound-proof-consumers` (48153b2), lens `feat/accumulation`
(3cf2aaa), nox `release/0.4` (2f09ca3); rest as stand B. Apple M4 Max,
shared with other agents (load 17–35).

## relation

| | before (#51) | now |
|---|---|---|
| columns | 64 + 15 | 64 + 15 |
| constraints | ~430 | 604 |
| degree | 8 | 8 (new constraints ≤ 7) |
| opcodes | 0–9 but lt, 15 | 0–17 |
| axis | `< 2^32` (AX1 + AX2, 2 rows per level) | `< p` (AXW, 1 row per level, ≤ 63) |

Trace rows (`ZHENG_DRY=1 machine_bench`, same programs):

| fixture | cycles | rows before | rows now |
|---|---|---|---|
| add.tri | 33 | 1 × 2^8 | 1 × 2^8 |
| hash.tri | 61 | 1 × 2^10 | 1 × 2^10 |
| merkle-32 | 1,121 | 2 × 2^14 | 2 × 2^14 |
| tree-12 | 16,383 | 3 × 2^14 | 3 × 2^14 |
| rec-14 | 393,202 | 61 × 2^14 | 53 × 2^14 |

## tests (`--release`, stand R2)

- zheng workspace: 283 passed, 0 failed, 5 ignored.
- `machine::tests_ops` (8 tests): 36 lt/word cases and a nested word
  program, 8 axis addresses from `2^32 + 3` to `p − 1`, calls with atom
  and pair witnesses, looks over authenticated tables — output and cycles
  equal `nox::reduce`'s, every constraint holds on every row; 17 native
  failure classes fail in the machine; exact budget passes and one fewer
  fails (lt, shl, not); 29 tampered cells violate the relation; the
  non-canonical aliases `v + p` of an lt operand and of an axis address
  satisfy every constraint except the canonical check, on exactly its row;
  a proof using every new opcode verifies with its evidence and fails with
  no evidence, another state's evidence, a forged read or another root;
  the profile-4 envelope round-trips the state.
- joy `feat/accumulation` against this branch: 224 passed, 0 failed, 1
  ignored.

## found during the work

- A generic B1 frame row (`TAG_B1 + op`, op a column) without a
  restriction on `op` could consume any other frame (a BR frame, a CALL
  frame) and evaluate its payload as a formula. Fixed before the first
  commit: `op` is restricted to the nine B1 opcodes by a degree-split
  product; a tampered `R_OP` / `R_OPY` cell is in the test list.

## rec-16 on the post-review code (#51 head 75f3846)

`ZHENG_TIMING=1 ZHENG_RATE=4 machine_bench rec-16` (rate 1/16, k = 4,
grinding 24, segments of 2^14 rows), binary built from `feat/accumulation`
75f3846 before this branch's changes, started 20:13 UTC, one run; load
average 7–72 during the run (other agents), so times are upper bounds of a
quiet machine. It **completed**:

| cycles | rows | AIR | 241 accumulation steps | decider | prove total | proof B (air · acc · decider) | verify (median of 3) | peak RSS |
|---|---|---|---|---|---|---|---|---|
| 1,572,850 | 241 × 2^14 = 3,948,544 | 1,028 s | 4,831 s (~20 s/step) | 55 s | 5,914 s (98.6 min) | 26,949,860 (2,015,728 · 24,842,210 · 91,909) | 3,927 ms (AIR ~0.5 s, steps ~3.4 s, decider ~5 ms) | 7.2 GB |

`/usr/bin/time`: 5,929 s real, 40,395 s user. The rec-16 row of
`accumulation-2026-10.md` §3 is these numbers. With this branch's
single-phase axis walk the same program's trace is shorter (rec-14: 61 →
53 segments); rec-16 was not rerun on this branch.

## not done

- No independent review of the new constraints (the phase-3 review
  covered the relation of #51).
- The bit-flip scan (`tests/machine.rs`, ignored, ~6 min) was not rerun
  on the new envelope form.
