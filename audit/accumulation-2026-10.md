---
tags: zheng, audit, accumulation, machine, phase 3
crystal-type: audit
crystal-domain: crypto
---
# accumulation and the nox machine — 2026-10-09

Work package F of the proof-system repair (soft3
`proposals/proof-system-repair.md` §3 "unbounded programs", §4, §5 phase 3).
What was built, what it measures against the phase-3 gates, and what is not
done. Contracts: `specs/machine.md`, `specs/accumulation.md`,
`specs/soundness.md` § machine proofs and accumulation.

Stand: zheng `feat/accumulation` (rebased onto `docs/proof-repair-ledger`, PR #50, itself on #49), lens
`feat/accumulation` (on `perf/batched-merkle` aee14d9), joy
`feat/accumulation` (on `feat/zk-and-state-binding`, joy #36); hemera
`perf/permutation-neon`, nox / trident `release/0.4` unchanged. Machine: Apple
M4 Max, 16 cores, 48 GB, macOS 26.4, rustc 1.95.0, `--release`, no LTO.
**The machine was shared with other agents during every run (load average
17–58); times are single runs under that load and are upper bounds of a
quiet machine. Sizes are deterministic.**

## 1. what was built

| piece | where | status |
|---|---|---|
| uniform step relation for nox | `rs/src/machine/` | built, tested (§4); one fixed row relation, 64 + 15 columns, degree 8, ~430 constraints; the verifier key is the constraint structure, a program enters through public columns and five constants |
| AIR proving over segments | `rs/src/air/` | built: zerocheck over rows, successor polynomial, public columns, shared lookup challenges across segments, boundary rows |
| accumulation of RS evaluation claims + decider | `rs/src/accumulate/` | built: WARP's claim-carrying structure for RS codes (not ARC verbatim — §5) |
| fold of N statements of one CCS relation | `accumulate::ccs` | built: 512 statements → one decider |
| envelope profile 4 (machine) | `rs/src/envelope/machine.rs` | built |
| lens: WHIR over Fp3 messages, leaf access | lens `rspcs/src/whir/access.rs` | built (base commitments, transcripts and bytes unchanged) |
| joy `prove --succinct` falls back to the machine | joy `rs/machine_execution.rs` | built |
| recursion `verify(verify(π))` | — | **not built** (§7) |

## 2. columns of the tables

`cycles` = nox's charged cost (`nox::reduce` budget spent); `rows` = trace
rows (init + machine steps + padding + permutation blocks) as
`segments × 2^n`; `proof B` = `MachineProof::to_bytes` (AIR messages of
every segment + one accumulation step per segment + the decider; the
envelope adds the statement and an 8-byte header); `air`, `acc`, `decider` =
its three parts; `prove` = AIR + accumulation + decider (excludes the native
run); `verify` = `machine::verify` from the parsed proof (median of 3).

## 3. measurements

### shipped WHIR parameters (rate 1/64, k = 4, grinding 24, Johnson)

Command: `ZHENG_TIMING=1 ZHENG_SEG=16 machine_bench add.tri hash.tri merkle-32`.

| fixture | cycles | rows | proof B | air | acc | decider | prove ms | verify ms |
|---|---|---|---|---|---|---|---|---|
| add.tri (7, 5) | 33 | 1 × 2^8 | 83,408 | 6,760 | 32,658 | 43,977 | 55,788 | 6.67 |
| hash.tri (7) | 61 | 1 × 2^10 | 96,968 | 7,296 | 37,042 | 52,617 | 49,322 | 5.43 |
| merkle-32 (32-hash path) | 1,121 | 1 × 2^15 | 145,500 | 8,636 | 49,762 | 87,089 | 184,786 | 8.64 |

Verifier parts (`ZHENG_TIMING`, medians of 3): hash.tri AIR 0.8 ms, the
accumulation step 1.6 ms, the decider 3.1 ms; merkle-32 AIR 1.0 ms, step
2.0 ms, decider 4.6 ms. Prover: grinding (24 bits per query round and per
WHIR fold) dominates; the AIR is under a second at hash.tri. Prove times in
this table were taken at load 40–60 and vary ×3 between runs. For reference, the one-relation succinct profile proves hash.tri in
15,921 B and verifies in 7.96 ms (`succinct-profile-2026-10.md` §4).

### long runs (rate 1/16, k = 4, grinding 24, Johnson; segments of 2^14 rows)

Command: `ZHENG_TIMING=1 ZHENG_RATE=4 machine_bench tree-1 tree-8 tree-12`
and `… rec-16`. `tree-k`: a balanced tree of `2^k` additions (`4·2^k − 1`
cycles); `rec-n`: a self-referencing doubling recursion `f(n) = 2^n` over
`~2^{n+1}` computed-formula calls (a program of tens of tokens).

| fixture | N = cycles | rows | proof B | air | acc | decider | prove ms | verify ms |
|---|---|---|---|---|---|---|---|---|
| tree-1 | 7 | 1 × 2^7 | 93,284 | 6,492 | 36,258 | 50,521 | 46,993 | 4.97 |
| tree-8 | 1,023 | 1 × 2^12 | 140,924 | 7,832 | 53,266 | 79,813 | 76,452 | 11.33 |
| tree-12 | 16,383 | 3 × 2^14 | 383,938 | 25,096 | 266,248 | 92,581 | 160,347 | 40.15 |
| rec-16 | 1,572,850 | 241 × 2^14 | — | — | — | — | not finished | — |

rec-16 (1.57M cycles, 3,948,544 rows) was started on the pre-review code
(before fresh-word OOD answers): the AIR of all 241 segments took 1,483 s
(24.7 min, 3.0 GB resident); its 241 accumulation steps were still running
at the time of writing (log `/tmp/wpf/bench_rec16.log` on the stand machine).
No size or verify time is claimed for it. Per step measured on tree-12 (an
earlier run, load ~20): AIR 5.2 s, one accumulation step 14.1 s; the
decider once, 33.7 s. Per segment the proof grows by the
segment's AIR messages (~8.3 KB) and its accumulation step (~88 KB: three
words — the accumulator and the segment's two — each opened at `t = 53`
positions with Merkle paths).

### the accumulator

`AccConfig` at grinding 24 (`accumulate::tests::config_table`):

| rate | ℓ | regime | t | s | claims | instance as encoded | compressible to |
|---|---|---|---|---|---|---|---|
| 1/16 | 20 | Johnson(19) | 53 | 1 | 55 | 27,977 B | 2,068 B |
| 1/16 | 21 | Johnson(19) | 53 | 1 | 55 | 29,297 B | 2,092 B |
| 1/64 | 20 | Johnson(7) | 36 | 1 | 38 | 19,341 B | 1,592 B |
| 1/64 | 21 | Johnson(7) | 36 | 1 | 38 | 20,253 B | 1,616 B |

The accumulator is constant in the number of steps: one root, `1 + s + t`
claims. It is never sent in a proof (the verifier derives it); "compressible"
counts root, `ρ`, values, OOD points and `t` symbol indices instead of
`pow(x)` points — the encoding a PCD would ship.

### 512 statements of one relation into one decider

`execution::succinct::fold_tests`: joy's hash.tri on inputs 0..511, each
statement's Spartan IOP down to its witness claim (committed free half,
`ℓ = 10`), accumulated 64 words per step (8 steps), one decider. Test
parameters (rate 1/8, grinding 16):

| total B | per-statement claim | 8 steps | decider | verify ms |
|---|---|---|---|---|
| 8,906,708 | 2,748 | 7,464,447 | 35,277 | 1,171 |

Against 512 independent succinct proofs (~16 KB each at the shipped
parameters, ~8.2 MB): one WHIR opening instead of 512, the same order of
bytes — the per-word spot checks of the accumulation steps are what a
verifier reads.

### joy

`joy prove --succinct` on a 600-iteration trident loop (`x = x·x + 1`; the
relation compiler refuses its nesting) falls back to the machine: 13,825
reductions, 455,141 B envelope, 366 s (shipped parameters, load ~50),
`joy verify` 36 ms; a wrong claim and wrong inputs are refused. The CI test
(140 iterations) proves and verifies in 120 s.

## 4. soundness tests

- 20 single-opcode programs, joy's compiled hash.tri (inputs 7, 0, p−1) and
  add.tri ((7,5), (0,0), (p−1,3)), the 11-hash chain, Merkle-8, tree and rec
  programs: output noun and cycles equal `nox::reduce`'s; every constraint
  holds on every row (single segment) — `machine::tests`, `tests/machine.rs`;
- every native failure class (atom formula, unknown opcode, add on a pair,
  axis through an atom, inverse of zero, branch on a pair, budget one short)
  is a machine failure;
- tampered result atom, cycle count, frame id, permutation state and init
  entry violate the relation;
- forged input, cycles, output, program; a lying Merkle root; swapped
  segments; weak/truncated/extended envelopes: rejected;
- accumulation: false input claim, forged openings, other roots, bit flips
  of a step, wrong accumulator claims and decider value: rejected;
- 512-statement fold: a statement with another output, a forged witness
  claim, a dropped step: rejected;
- an independent read-only review of the constraint system and the AIR
  protocol found no under-constrained cell, memory hole or control-flow
  escape (notes applied: a comment, the running-sum pin's role);
- **bit-flip scan** of a full machine envelope (add.tri, shipped
  parameters, after the review fixes): 83,593 bytes, 668,744 flips,
666,280 decoded, **0 accepted** (385 s; before the fixes: 82,705 B, 661,640
flips, 0 accepted).

## 4b. review fixes

An independent soundness review (no break found) asked for: fresh words
bound by out-of-domain answers before any challenge they feed (AIR phase-1
and phase-2 words, CCS witnesses — done, `air::commit_bound`,
`accumulate::fresh_ood`); interactive vs ROM bounds separated in the ledger;
citations corrected (Lemma 4.13 argument with BCGM Def 3.14; OOD = WHIR Lemma
4.25); `AccConfig` refuses deciders below 128 bits and steps over
`max_claims`; the prover refuses a word whose data is not its instance; wire
docs fixed; lens serde round-trips Fp3 proofs; a domain string for CCS claim
proofs. Tests for each; sizes above are after these fixes.

## 5. which accumulation, and why

Implemented: **WARP's claim-carrying structure (eprint 2025/753 §6
pseudo-batching, Construction 7.2 codeword batching) instantiated for
Reed–Solomon codes**, with univariate out-of-domain samples as in ARC
(eprint 2024/1731 §2.1) and WHIR, the powers generator in one combination
round, and claims carried instead of WARP §8's constraint batching. Not ARC
verbatim: ARC's quotient step needs a per-step Fill message and FFT over
Fp3, its NP accumulation carries two oracles, and its stated Johnson-regime
proximity error is weaker than the mutual-correlated-agreement bound (BCGM
2025/2051 Lemma 9.3) lens already relies on; the claim-carrying form lets
the existing multilinear WHIR opening be the decider. The round-by-round
argument (`specs/accumulation.md` § soundness) composes the cited lemmas for
this protocol; it is mine, not a paper's theorem, and has not had an
external review.

## 6. against the gates (proposal §5, phase 3)

| gate | measured | verdict |
|---|---|---|
| merkle-32 proves | 145,500 B, verify 8.6 ms | proves; **misses ≤ 64 KB** (2.3×) |
| a 10^6-step run proves | rec-16, 1,572,850 cycles: native agreement and trace built (`long_runs_agree_with_native_nox` checks rec-14, 393,202 cycles); its proof did not finish in this package | **not shown** |
| size independent of length, ≤ 64 KB | 83 KB (33 cycles) … 146 KB (merkle-32) … 384 KB (16,383 cycles) — linear in the number of segments (~96 KB per 2^14-row segment) | **missed** |
| verify ≤ 1 ms | 5.4 ms (hash.tri) … 8.3–8.6 ms (merkle-32) … 40 ms (3 segments) | **missed** |
| bit-flip scan of a full accumulated proof: 0 accepted | 668,744 flips, 0 accepted | **met** |
| `verify(verify(π))` at depth 2 | not built | **missed** (§7) |
| 512 tickets decide in one proof | 8.9 MB, verify 1.17 s, one decider | met as an API; foculus wiring is another package |

**Why size is linear.** Accumulation reduces `N` claims to one decider, but
each step's proof (spot checks in every folded word) must be checked by
someone. Without recursion the final verifier checks every step, so the
proof carries every step: bytes and verifier time are linear in the number
of segments. Proposal §4's "accumulation … no verifier circuit is ever
built … this is how 'any computation' is proven at constant size" does not
hold: constant size needs the accumulation verifier inside the next step's
relation (PCD, ARC §2.3 / WARP §1), which is recursion. Measured here: one
accumulation step costs ~88 KB of openings at `ℓ = 20` (rate 1/16) — more
than the WHIR opening it replaces.

**Why merkle-32 misses 64 KB.** The trace is `2^15 × 64` cells: each level
re-derives the structural digest of two fresh digest nouns (4 atom digests
of 2 permutations + 3 pair digests each) plus the pair and the hash opcode —
~24 hemera permutations of 32 rows per level. The decider alone (WHIR over
an Fp3 word at `ℓ = 21`) is 87 KB; the accumulation step folding the two
committed words is 50 KB. Levers not taken: a narrower permutation trace
(perm rows use 22 of 64 columns), batched WHIR over both words instead of an
accumulation step, compressed accumulator encodings.

**Why verify is ms, not µs.** The machine AIR verifier itself is cheap
(constraint evaluation once per segment); the time is hemera Merkle paths in
the accumulation step and the decider (~5–8 ms per segment-step and
decider at these parameters).

## 7. not done

- **Recursion.** No relation expresses the accumulation step's or the
  decider's verifier, so there is no `verify(verify(π))` fixture and no
  decider-as-relation. What it needs, measured against this stand: the
  lens transcript and Merkle leaves hash *bytes* (7 bytes per element), so
  every absorbed Fp3 element and every leaf symbol needs an in-relation
  byte decomposition (the machine's atom-digest bits rows are that gadget);
  Fp3 arithmetic rows; hemera node rows (the machine's `PAIR` job is
  `hash_node` without the root flag); the WHIR schedule is static. One
  accumulation step at `ℓ = 20` checks `3 × 53` leaves with ~15-level
  paths: ≈ 2,400 node permutations + ≈ 160 leaf sponges + ≈ 300
  transcript permutations ≈ 3,000 permutations ≈ 96K permutation rows plus
  byte decompositions — a 2^17-row relation per step before the
  segment's own rows. Not started.
- Constant proof size and ≤ 1 ms verification (follow from recursion).
- The 64 KB bound for merkle-32 (levers in §6).
- Opcodes lt, xor/and/not/shl, call, look; axis addresses ≥ 2^32 (refused,
  never proven wrongly).
- The arena capacity of `nox::Reduction<N>` is not modelled; the budget
  equivalence relies on nox's `bound()` being an upper bound (review checked
  the covered opcodes).
- foculus wiring of `accumulate::ccs` (another package); lattice-fold spike
  (proposal §B); zip.
- A compressed wire form of an accumulator instance (only needed once
  accumulators travel, i.e. with PCD).
