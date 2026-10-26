---
tags: zheng, audit, recursion, wrap, hemera 0.4
date: 2026-10-26
---
# The wrap chain's frontier under hemera 0.4, 2026-10-26

The soft3 director's plan, row L3b. Under hemera 0.4 (profile #15, decision 2026-10-16) the shipped wrap chain's final proof breaks `specs/recursion.md`'s hard 64 KiB gate (`wrap::MAX_FINAL_BYTES` = 65,536). This report measures whether **any** chain fits under that gate with λ fixed, and at what prover cost. λ is never lowered here: every ledger row is wrap's own derivation and must be ≥ 128 bits, or the key is refused. The owner decides the limit (zheng#73). This page only measures.

## sources

| what | revision | run |
|---|---|---|
| zheng | `ci/hemera-0.4-sweep` `4c9005e` (zheng#73) + `diag/l3-sweep-fix`'s census printout + one workflow = `diag/l3b-frontier` `3dbd00a`, never merged | **40273927146** (2026-10-26 05:23–06:43 UTC) |
| hemera, lens, nox | `release/0.4`, `release/0.2`, `release/0.4` | same |
| runner | GitHub `ubuntu-latest`, 4 × AMD EPYC 7763, 16 GiB, `--release` | same |

- **shape**: `cargo run --release -p zheng --example wrap_chain -- <chains>` plans each chain without proving. It prints each level's rows, queries and weakest ledger bits, and `final proof ≤ N B over every transcript` (`wrap::max_proof_bytes` of the final key, the bound the gate tests).
- **time**: `wrap_bench add.tri` proves the chain end to end under `/usr/bin/time -v`.
- The grid: IVC rate 1/16 at 2^15 steps (`4:15`, the only 2^15 IVC that fits, L3b(2)) and 1/8 at 2^16 (`3:16`). Inner chains `4i:16,7i:22` (shipped), `4i:16,6i:22`, `4i:16,8i:24`, `5i:18,7i:22`, `4i:16,7i:22,8i:24`. Final level rate 1/2^8 … 1/2^13 × grinding 22, 24 … 30 bits × fold 3, 4, 5. That is 900 chains, in the artifacts `shape-*`/`shape.txt` and `time-*`/`time.txt` of run 40273927146.

## results — size (shape, 900 chains)

| outcome | chains |
|---|---|
| a byte bound (key derived, λ ≥ 128) | 500 |
| bound ≤ 65,536 B | **0** |
| refused at final rate 1/2^11, fold 4 and 5: `whir: … bits < 128` (116.4–124.9 bits at grinding 22–30) | 100 |
| refused at final rate 1/2^12 and 1/2^13: `whir: size outside supported range` | 300 |

- **The smallest bound is 66,921 B** (`4i:16,7i:22,10f:30:5`), 1,385 B over the gate.
- **The shipped chain `9f:26` (fold 4) bounds at 74,525 B.** That is the figure of zheng#73's run 40272079660, reproduced.
- **The inner chain does not move the final bound.** For every (IVC, final) pair, all five inner chains give one value. The final circuit is 20,735–25,850 rows depending on the inner chain, but always 2^15. So the final level's parameters set the bytes.
- **The IVC rate does not move it either**: 1/8 at 2^16 is +24 B against 1/16 at 2^15 at every final.
- **2^14 is out of reach.** The smallest final circuit swept is 20,735 rows (`4i:16,7i:22,8i:24`) against 16,384. Permutation rows alone, 6 per permutation at hemera 0.4 (4 before), are 16,938 of the shipped final's 23,921.
- The bound falls with grinding and fold. At `10f:*:5` it goes 72,413 (22) → 70,133 (24, 26) → 67,821 (28) → 66,921 (30). **The sweep stopped at 30 bits before the trend did** (round 2 below).

The final levels on the shipped inner chain (`4i:16,7i:22`), from run 40273927146:

| final (rate·grind·fold) | rows → 2^n | final λ bits | queries | bound B, IVC 1/16 at 2^15 | bound B, IVC 1/8 at 2^16 |
|---|---|---|---|---|---|
| `8f:22:3` | 23921 → 2^15 | 128.24 | 28, 22, 19, 16, 14 | 88257 | 88281 |
| `8f:22:4` | 23921 → 2^15 | 128.24 | 28, 20, 16, 13 | 79101 | 79125 |
| `8f:22:5` | 23921 → 2^15 | 128.24 | 28, 19, 14 | 78529 | 78553 |
| `8f:24:3` | 23921 → 2^15 | 128.26 | 27, 22, 18, 16, 14 | 86777 | 86801 |
| `8f:24:4` | 23921 → 2^15 | 128.29 | 27, 20, 16, 13 | 78361 | 78385 |
| `8f:24:5` | 23921 → 2^15 | 128.29 | 27, 18, 14 | 76377 | 76401 |
| `8f:26:3` | 23921 → 2^15 | 128.11 | 27, 21, 18, 15, 13 | 84461 | 84485 |
| `8f:26:4` | 23921 → 2^15 | 128.18 | 27, 19, 15, 13 | 76433 | 76457 |
| `8f:26:5` | 23921 → 2^15 | 128.29 | 27, 18, 14 | 76377 | 76401 |
| `8f:28:3` | 23921 → 2^15 | 128.04 | 26, 21, 17, 15, 13 | 82981 | 83005 |
| `8f:28:4` | 23921 → 2^15 | 128.18 | 26, 19, 15, 12 | 74761 | 74785 |
| `8f:28:5` | 23921 → 2^15 | 128.11 | 26, 17, 13 | 72909 | 72933 |
| `8f:30:3` | 23921 → 2^15 | 128.01 | 25, 20, 17, 15, 13 | 81469 | 81493 |
| `8f:30:4` | 23921 → 2^15 | 128.05 | 25, 19, 15, 12 | 74021 | 74045 |
| `8f:30:5` | 23921 → 2^15 | 128.05 | 25, 17, 13 | 72073 | 72097 |
| `9f:22:3` | 23921 → 2^15 | 128.16 | 25, 21, 17, 15, 13 | 85185 | 85209 |
| `9f:22:4` | 23921 → 2^15 | 128.11 | 25, 19, 15, 13 | 77257 | 77281 |
| `9f:22:5` | 23921 → 2^15 | 128.43 | 25, 17, 13 | 73833 | 73857 |
| `9f:24:3` | 23921 → 2^15 | 128.16 | 24, 20, 17, 15, 13 | 83609 | 83633 |
| `9f:24:4` | 23921 → 2^15 | 128.16 | 24, 18, 15, 12 | 74525 | 74549 |
| `9f:24:5` | 23921 → 2^15 | 128.43 | 24, 17, 13 | 72965 | 72989 |
| `9f:26:3` | 23921 → 2^15 | 128.27 | 24, 19, 17, 14, 13 | 81969 | 81993 |
| `9f:26:4` | 23921 → 2^15 | 128.16 | 24, 18, 15, 12 | 74525 | 74549 |
| `9f:26:5` | 23921 → 2^15 | 128.43 | 24, 17, 13 | 72965 | 72989 |
| `9f:28:3` | 23921 → 2^15 | 128.27 | 23, 19, 16, 14, 12 | 79653 | 79677 |
| `9f:28:4` | 23921 → 2^15 | 128.11 | 23, 17, 14, 12 | 71761 | 71785 |
| `9f:28:5` | 23921 → 2^15 | 128.34 | 23, 16, 13 | 70749 | 70773 |
| `9f:30:3` | 23921 → 2^15 | 128.27 | 23, 19, 16, 14, 12 | 79653 | 79677 |
| `9f:30:4` | 23921 → 2^15 | 128.11 | 23, 17, 14, 12 | 71761 | 71785 |
| `9f:30:5` | 23921 → 2^15 | 128.33 | 23, 16, 12 | 69401 | 69425 |
| `10f:22:3` | 23921 → 2^15 | 128.11 | 23, 19, 16, 14, 13 | 83145 | 83169 |
| `10f:22:4` | 23921 → 2^15 | 128.33 | 23, 17, 14, 12 | 73873 | 73897 |
| `10f:22:5` | 23921 → 2^15 | 128.11 | 23, 16, 13 | 72413 | 72437 |
| `10f:24:3` | 23921 → 2^15 | 128.11 | 22, 19, 16, 14, 12 | 81569 | 81593 |
| `10f:24:4` | 23921 → 2^15 | 128.11 | 22, 17, 14, 12 | 73069 | 73093 |
| `10f:24:5` | 23921 → 2^15 | 128.11 | 22, 16, 12 | 70133 | 70157 |
| `10f:26:3` | 23921 → 2^15 | 128.11 | 22, 18, 16, 14, 12 | 80701 | 80725 |
| `10f:26:4` | 23921 → 2^15 | 128.05 | 22, 17, 14, 11 | 72073 | 72097 |
| `10f:26:5` | 23921 → 2^15 | 128.11 | 22, 16, 12 | 70133 | 70157 |
| `10f:28:3` | 23921 → 2^15 | 128.11 | 21, 18, 15, 13, 12 | 78225 | 78249 |
| `10f:28:4` | 23921 → 2^15 | 128.05 | 21, 16, 13, 11 | 69213 | 69237 |
| `10f:28:5` | 23921 → 2^15 | 128.33 | 21, 15, 12 | 67821 | 67845 |
| `10f:30:3` | 23921 → 2^15 | 128.11 | 20, 17, 15, 13, 12 | 76585 | 76609 |
| `10f:30:4` | 23921 → 2^15 | 128.05 | 20, 16, 13, 11 | 68409 | 68433 |
| `10f:30:5` | 23921 → 2^15 | 128.25 | 20, 15, 12 | 66921 | 66945 |
| `11f:22:3` | 23921 → 2^15 | 128.16 | 21, 17, 15, 13, 12 | 79853 | 79877 |
| `11f:22:4` | — | — | — | refused: whir: 116.93 bits < 128 (circuit 23921 rows → 2^15) | refused: whir: 116.93 bits < 128 (circuit 23922 rows → 2^15) |
| `11f:22:5` | — | — | — | refused: whir: 116.43 bits < 128 (circuit 23921 rows → 2^15) | refused: whir: 116.43 bits < 128 (circuit 23922 rows → 2^15) |
| `11f:24:3` | 23921 → 2^15 | 128.16 | 20, 17, 15, 13, 12 | 79049 | 79073 |
| `11f:24:4` | — | — | — | refused: whir: 118.93 bits < 128 (circuit 23921 rows → 2^15) | refused: whir: 118.93 bits < 128 (circuit 23922 rows → 2^15) |
| `11f:24:5` | — | — | — | refused: whir: 118.43 bits < 128 (circuit 23921 rows → 2^15) | refused: whir: 118.43 bits < 128 (circuit 23922 rows → 2^15) |
| `11f:26:3` | 23921 → 2^15 | 128.05 | 20, 17, 15, 13, 11 | 78213 | 78237 |
| `11f:26:4` | — | — | — | refused: whir: 120.93 bits < 128 (circuit 23921 rows → 2^15) | refused: whir: 120.93 bits < 128 (circuit 23922 rows → 2^15) |
| `11f:26:5` | — | — | — | refused: whir: 120.43 bits < 128 (circuit 23921 rows → 2^15) | refused: whir: 120.43 bits < 128 (circuit 23922 rows → 2^15) |
| `11f:28:3` | 23921 → 2^15 | 128.05 | 19, 16, 14, 13, 11 | 75609 | 75633 |
| `11f:28:4` | — | — | — | refused: whir: 122.93 bits < 128 (circuit 23921 rows → 2^15) | refused: whir: 122.93 bits < 128 (circuit 23922 rows → 2^15) |
| `11f:28:5` | — | — | — | refused: whir: 122.43 bits < 128 (circuit 23921 rows → 2^15) | refused: whir: 122.43 bits < 128 (circuit 23922 rows → 2^15) |
| `11f:30:3` | 23921 → 2^15 | 128.05 | 19, 16, 14, 12, 11 | 74741 | 74765 |
| `11f:30:4` | — | — | — | refused: whir: 124.93 bits < 128 (circuit 23921 rows → 2^15) | refused: whir: 124.93 bits < 128 (circuit 23922 rows → 2^15) |
| `11f:30:5` | — | — | — | refused: whir: 124.43 bits < 128 (circuit 23921 rows → 2^15) | refused: whir: 124.43 bits < 128 (circuit 23922 rows → 2^15) |
| `12f:22:3` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `12f:22:4` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `12f:22:5` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `12f:24:3` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `12f:24:4` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `12f:24:5` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `12f:26:3` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `12f:26:4` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `12f:26:5` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `12f:28:3` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `12f:28:4` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `12f:28:5` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `12f:30:3` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `12f:30:4` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `12f:30:5` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `13f:22:3` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `13f:22:4` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `13f:22:5` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `13f:24:3` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `13f:24:4` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `13f:24:5` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `13f:26:3` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `13f:26:4` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `13f:26:5` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `13f:28:3` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `13f:28:4` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `13f:28:5` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `13f:30:3` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `13f:30:4` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |
| `13f:30:5` | — | — | — | refused: ood: whir: size outside supported range or inconsistent with proof | refused: ood: whir: size outside supported range or inconsistent with proof |

## results — prover time (time, IVC 1/16 at 2^15, `add.tri`)

| chain | outcome | final proof | wrap 0 / 1 / 2 prove | wall (incl. ~1 min build) | peak RSS |
|---|---|---|---|---|---|
| `4i:16,7i:22,9f:26` (shipped) | proved | **72,957 B** (header 49 · claim 1,272 · air 5,264 · opening 66,372), verify 7.58 ms | 131 s / 829 s / **3,089 s** | 1:19:25 | 13.1 GiB |
| `4i:16,7i:22,10f:28` | **no result**: the runner received a shutdown signal at 44 min (exit 143). The cause is not established | — | — | — | — |
| `4i:16,7i:22,11f:28` | refused at the final key: `whir: 122.93 bits < 128` (as shape predicts) | — | 167 s / 1,062 s / — | 35:34 | 6.1 GiB |
| `4i:16,7i:22,12f:30` | refused at the final key: `whir: size outside supported range` (as shape predicts) | — | 151 s / 956 s / — | 32:15 | 6.1 GiB |

Every job also proved the IVC (`add.tri`, 33 cycles, 437,085 B, 106–135 s) and wrap 0 (259,760 B) and wrap 1 (192,884 B). The measured shipped proof (72,957 B) is under its bound (74,525 B), as a bound must be. On 4 CPU threads the final level dominates: 3,089 s of a 4,049 s chain prove at 1/512. A chain at 1/1024 (the smallest bounds) has twice the final codeword, and it has not been timed.

## round 2 — grinding 30 … 40, fold 5 … 8

Run **40287282242** (`diag/l3b-frontier-2` `bbeaab1` = round 1's base + one workflow, never merged). The same runner and lines. Shape only, on the shipped inner chain at IVC 1/16, 2^15 (round 1: the inner chain and the IVC rate do not move the final bound). Final rate 1/2^8 … 1/2^10 × grinding 30, 32 … 40 × fold 5 … 8: 72 chains, 70 with a bound, 2 refused (`10f:30:6` 124.93 bits, `10f:32:6` 126.93 bits).

**8 chains bound ≤ 65,536 B.** All are at fold 5. Folds 6–8 are larger at every point (75,057–165,981 B):

| final | bound B | under the gate by | final λ bits | queries |
|---|---|---|---|---|
| `10f:40:5` | 59,537 | 5,999 | 128.11 | 18, 13, 10 |
| `10f:38:5` | 61,817 | 3,719 | 128.08 | 19, 13, 11 |
| `9f:40:5` | 62,689 | 2,847 | 128.01 | 20, 14, 11 |
| `10f:36:5` | 63,229 | 2,307 | 128.07 | 19, 14, 11 |
| `9f:38:5` | 63,557 | 1,979 | 128.01 | 21, 14, 11 |
| `10f:32:5`, `10f:34:5` | 64,129 | 1,407 | 128.07 | 20, 14, 11 |
| `9f:36:5` | 64,937 | 599 | 128.01 | 21, 15, 11 |

At rate 1/2^8, even 40 bits do not fit (66,421 B). The full grid of round 2:

| final (rate·grind·fold) | rows → 2^n | final λ bits | queries | bound B, IVC 1/16 at 2^15  |
|---|---|---|---|--- |
| `8f:30:5` | 23921 → 2^15 | 128.05 | 25, 17, 13 | 72073  |
| `8f:30:6` | 23921 → 2^15 | 128.05 | 25, 16, 12 | 94473  |
| `8f:30:7` | 23921 → 2^15 | 128.05 | 25, 15 | 104401  |
| `8f:30:8` | 23921 → 2^15 | 128.05 | 25, 14 | 165981  |
| `8f:32:5` | 23921 → 2^15 | 128.05 | 25, 17, 13 | 72073  |
| `8f:32:6` | 23921 → 2^15 | 128.01 | 25, 15, 11 | 90337  |
| `8f:32:7` | 23921 → 2^15 | 128.05 | 25, 14 | 100813  |
| `8f:32:8` | 23921 → 2^15 | 128.05 | 25, 13 | 159353  |
| `8f:34:5` | 23921 → 2^15 | 128.13 | 24, 16, 12 | 68605  |
| `8f:34:6` | 23921 → 2^15 | 128.01 | 24, 15, 11 | 89277  |
| `8f:34:7` | 23921 → 2^15 | 128.07 | 24, 14 | 99273  |
| `8f:34:8` | 23921 → 2^15 | 128.13 | 24, 13 | 156821  |
| `8f:36:5` | 23921 → 2^15 | 128.33 | 24, 16, 12 | 68605  |
| `8f:36:6` | 23921 → 2^15 | 128.01 | 24, 15, 11 | 89277  |
| `8f:36:7` | 23921 → 2^15 | 128.07 | 24, 14 | 99273  |
| `8f:36:8` | 23921 → 2^15 | 128.21 | 24, 13 | 156821  |
| `8f:38:5` | 23921 → 2^15 | 128.21 | 23, 16, 12 | 67769  |
| `8f:38:6` | 23921 → 2^15 | 128.01 | 23, 14, 11 | 86133  |
| `8f:38:7` | 23921 → 2^15 | 128.08 | 23, 13 | 94145  |
| `8f:38:8` | 23921 → 2^15 | 128.21 | 23, 13 | 154289  |
| `8f:40:5` | 23921 → 2^15 | 128.09 | 23, 15, 12 | 66421  |
| `8f:40:6` | 23921 → 2^15 | 128.09 | 23, 14, 10 | 84081  |
| `8f:40:7` | 23921 → 2^15 | 128.09 | 23, 13 | 94145  |
| `8f:40:8` | 23921 → 2^15 | 128.09 | 23, 12 | 147661  |
| `9f:30:5` | 23921 → 2^15 | 128.33 | 23, 16, 12 | 69401  |
| `9f:30:6` | 23921 → 2^15 | 128.05 | 23, 15, 11 | 89785  |
| `9f:30:7` | 23921 → 2^15 | 128.34 | 23, 14 | 98917  |
| `9f:30:8` | 23921 → 2^15 | 128.11 | 23, 13 | 155441  |
| `9f:32:5` | 23921 → 2^15 | 128.01 | 22, 15, 12 | 67153  |
| `9f:32:6` | 23921 → 2^15 | 128.05 | 22, 14, 11 | 86577  |
| `9f:32:7` | 23921 → 2^15 | 128.08 | 22, 14 | 97345  |
| `9f:32:8` | 23921 → 2^15 | 128.08 | 22, 13 | 152877  |
| `9f:34:5` | 23921 → 2^15 | 128.01 | 22, 15, 12 | 67153  |
| `9f:34:6` | 23921 → 2^15 | 128.05 | 22, 14, 11 | 86577  |
| `9f:34:7` | 23921 → 2^15 | 128.08 | 22, 13 | 93725  |
| `9f:34:8` | 23921 → 2^15 | 128.08 | 22, 12 | 146217  |
| `9f:36:5` | 23921 → 2^15 | 128.01 | 21, 15, 11 | 64937  |
| `9f:36:6` | 23921 → 2^15 | 128.07 | 21, 14, 10 | 83401  |
| `9f:36:7` | 23921 → 2^15 | 128.07 | 21, 13 | 92153  |
| `9f:36:8` | 23921 → 2^15 | 128.07 | 21, 12 | 143653  |
| `9f:38:5` | 23921 → 2^15 | 128.01 | 21, 14, 11 | 63557  |
| `9f:38:6` | 23921 → 2^15 | 128.08 | 21, 13, 10 | 81285  |
| `9f:38:7` | 23921 → 2^15 | 128.43 | 21, 13 | 92153  |
| `9f:38:8` | 23921 → 2^15 | 128.33 | 21, 12 | 143653  |
| `9f:40:5` | 23921 → 2^15 | 128.01 | 20, 14, 11 | 62689  |
| `9f:40:6` | 23921 → 2^15 | 128.01 | 20, 13, 10 | 80193  |
| `9f:40:7` | 23921 → 2^15 | 128.01 | 20, 12 | 86961  |
| `9f:40:8` | 23921 → 2^15 | 128.01 | 20, 12 | 141089  |
| `10f:30:5` | 23921 → 2^15 | 128.25 | 20, 15, 12 | 66921  |
| `10f:30:6` | — | — | — | refused: whir: 124.93 bits < 128 (circuit 23921 rows → 2^15)  |
| `10f:30:7` | 23921 → 2^15 | 128.11 | 20, 13 | 91637  |
| `10f:30:8` | 23921 → 2^15 | 128.25 | 20, 12 | 142113  |
| `10f:32:5` | 23921 → 2^15 | 128.07 | 20, 14, 11 | 64129  |
| `10f:32:6` | — | — | — | refused: whir: 126.93 bits < 128 (circuit 23921 rows → 2^15)  |
| `10f:32:7` | 23921 → 2^15 | 128.11 | 20, 13 | 91637  |
| `10f:32:8` | 23921 → 2^15 | 128.25 | 20, 12 | 142113  |
| `10f:34:5` | 23921 → 2^15 | 128.07 | 20, 14, 11 | 64129  |
| `10f:34:6` | 23921 → 2^15 | 128.25 | 20, 13, 10 | 81569  |
| `10f:34:7` | 23921 → 2^15 | 128.25 | 20, 12 | 87985  |
| `10f:34:8` | 23921 → 2^15 | 128.25 | 20, 12 | 142113  |
| `10f:36:5` | 23921 → 2^15 | 128.07 | 19, 14, 11 | 63229  |
| `10f:36:6` | 23921 → 2^15 | 128.37 | 19, 13, 10 | 80445  |
| `10f:36:7` | 23921 → 2^15 | 128.33 | 19, 12 | 86381  |
| `10f:36:8` | 23921 → 2^15 | 128.33 | 19, 12 | 139517  |
| `10f:38:5` | 23921 → 2^15 | 128.08 | 19, 13, 11 | 61817  |
| `10f:38:6` | 23921 → 2^15 | 128.43 | 19, 13, 10 | 80445  |
| `10f:38:7` | 23921 → 2^15 | 128.33 | 19, 12 | 86381  |
| `10f:38:8` | 23921 → 2^15 | 128.05 | 19, 11 | 132825  |
| `10f:40:5` | 23921 → 2^15 | 128.11 | 18, 13, 10 | 59537  |
| `10f:40:6` | 23921 → 2^15 | 128.21 | 18, 12, 9 | 75057  |
| `10f:40:7` | 23921 → 2^15 | 128.21 | 18, 12 | 84777  |
| `10f:40:8` | 23921 → 2^15 | 128.05 | 18, 11 | 130229  |

## reading

- **A chain under 64 KiB exists, with λ ≥ 128, the queries derived and the shipped levels kept.** Every such chain moves the final level to fold 5 and raises its grinding from 26 bits to ≥ 32 (rate 1/1024) or ≥ 36 (rate 1/512). It is the owner's option (i) on zheng#73.
- **Its price is prover work, and it is not measured yet.** Grinding 2^32 is 64 times the shipped 2^26 per grinding round, and 2^36 is 1,024 times. Rate 1/1024 doubles the final codeword, whose 1/512 version already takes 3,089 s and 13.1 GiB on 4 threads. Round 3 measures that.
- **Option (ii)** raises the gate to the shipped chain's bound, 74,525 B (measured 72,957 B). It keeps today's prover time: 3,089 s for the final level, 1:19 for the whole chain on 4 threads.
- **Not swept:** a second final level, and circuit changes that would bring the final level to 2^14 (the 6 permutation rows of hemera 0.4). Neither is needed for (i) or (ii).
- Nothing here lowers λ, changes the query derivation or touches `MAX_FINAL_BYTES`. A spec PR and a code PR follow the owner's choice, each restating the chain, the 32768 ceiling (L3b(3)) and the IVC rate (L3b(2)).

## remains

- **Round 3**, run **40287758728** (`diag/l3b-frontier-2` `52dae14`, never merged, jobs up to 355 min): `wrap_bench add.tri` on `4i:16,7i:22,9f:36:5`, `4i:16,7i:22,10f:32:5`, and `4i:16,7i:22,9f:26:5` (the control: shipped grinding at fold 5, which separates the cost of fold from the cost of grinding). It reports the prover time and peak memory of option (i) on the 16 GiB runner. A runner shutdown or an out-of-memory kill is recorded as such, not read as a result.
- Why `10f:28`'s round-1 time job lost its runner at 44 min.
