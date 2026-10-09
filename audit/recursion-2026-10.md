---
tags: zheng, audit, recursion, ivc, machine
crystal-type: audit
crystal-domain: crypto
---
# recursion (IVC over the nox machine) — 2026-10-09

Work package of the proof-system repair (soft3
`proposals/proof-system-repair.md` §4, the release-blocking piece): proofs
of nox runs whose size does not depend on the run's length. Contract:
`specs/recursion.md`; ledger rows: `specs/soundness.md` § recursion.

Stand: zheng `feat/ivc` (on `feat/accumulation`, PR #51), lens
`feat/accumulation` 3cf2aaa, joy `feat/accumulation` 69a15ef, hemera
cf28a64. Machine: Apple M4 Max, 16 cores, 48 GB, rustc 1.95.0,
`--release`. **The machine was shared with other agents during every run
(load average 26–97); every time below is a single run (verify: median of
5) under that load and an upper bound of a quiet machine. Sizes are
deterministic.**

## 1. what was built

| piece | where | status |
|---|---|---|
| field-native transcript (duplex over hemera's permutation, rate 9) | `recursion/sponge.rs` | built |
| field-native committed words (lens RS layout, hemera Merkle over field elements) | `recursion/word.rs` | built |
| verifier operations written once over `Ops` (native / circuit) | `recursion/ops.rs`, `gm.rs` | built |
| recursion circuit: ARITH gates, 4-row hemera blocks, BITS, logUp memory, `live` | `recursion/circuit/` | built, tested |
| step relation = nox machine ‖ circuit, three words, deferred claims | `recursion/relation.rs`, `step.rs`, `prove.rs`, `acc.rs` | built |
| IVC driver, final verifier, wire format (deduplicated openings) | `recursion/ivc.rs`, `wire.rs` | built |
| `verify(verify(π))` | `tests/recursion.rs::a_two_step_proof_is_verify_of_verify` | passes |
| decider as a relation / a wrap step | — | **not built** (§6) |

The circuit verifying one step (AIR reduction of the previous step,
its four-word accumulation step with 53 spot checks and full Merkle paths,
the state digests, the base case) takes **27,444 of 32,768 rows** at rate
1/16 (13,534 gates, 56 decompositions, 5,959 permutation blocks) and
21,278 rows at rate 1/64 (`program::tests::circuit_size_at_the_shipped_parameters`).

## 2. parameters

WHIR rate 1/16, folding 4, 24 grinding bits, Johnson; steps of 2^15 rows
(nox segment and circuit side by side), words of ℓ = 21 variables;
accumulation of 4 words, 64 claims: t = 53, s = 1, query grinding 24,
combination grinding 22. Every ledger row ≥ 128 bits (table in
`specs/soundness.md` § recursion, checked by
`recursion::params::tests::every_ledger_row_of_the_recursion_profile_reaches_128_bits`).

## 3. measurements

Command: `ZHENG_TIMING=1 ivc_bench <fixture>` (`rs/examples/ivc_bench`).
`proof B` = `IvcProof::to_bytes` (header, the state the last step started
from, the last step, its accumulation step with deduplicated openings, the
decider). `verify` = `ivc::verify` from the parsed proof including the
statement-side preparation.

Rate 1/16 (the parameters of §2):

| fixture | cycles | steps × 2^15 rows | proof B | prove s (all steps + decider) | verify ms |
|---|---|---|---|---|---|
| add.tri (7, 5) | 33 | 1 | 284,382 | 101.8 | 24.5 |
| hash.tri (7) | 61 | 1 | 284,702 | 82.5 | 21.2 |
| merkle-32 | 1,121 | 1 | 282,814 | 128.8 | 18.5 |
| tree-12 | 16,383 | 2 | 282,206 | 172.6 | 38.4 |
| rec-16 | 1,572,850 | 121 | 284,446 | 3,812 (63.5 min; 31.5 s a step, decider included) | 17.9 |

The size is flat from 33 cycles to 1.57 million (121 steps): 282–285 KB;
the spread is the deduplication of the spot checks' paths, which depends
on where the transcript's positions fall. Verify times are under load and
vary ×2 between runs; they do not grow with the steps (the verifier
checks one step).

Rate 1/64 (the lever of §6; t = 36, ledger rows ≥ 128.2), add.tri: proof
**233,562 B** (state 17,688 · step 21,288 · accumulation 107,448 ·
decider 87,089), prove 81.2 s (step 41 s), verify 17.4 ms, 14.4 ms with
the statement-side preparation cached; the circuit takes 21,278 rows.
Memory per step about ×4 of rate 1/16 (Fp3 accumulator codeword 2^27
symbols).

Parts (bytes): header 49 · state 18,232 · step 21,288 ·
accumulation 139,004–141,180 · decider 103,633–104,209 (every fixture;
`IvcProof::sizes`). The state is constant: the accumulator (root, 21 + 2 +
53 claims), the three deferred claims (the constraint claim's point alone
is 531 Fp3 = 12.7 KB), boundary rows, digests.

Prover per step (add.tri, laps of `ZHENG_TIMING`, load ~30): circuit
build 0.1 s; words b and c 1.3 s each; zerocheck 2.7 s; deferred folds and
shift 0.2 s; accumulation 21 s (claim sumcheck 4.7 s, combination grinding
0.7 s, commit of the Fp3 accumulator 8 s, query grinding 7.4 s); the
decider once, 60–100 s (lens WHIR at ℓ = 21 over Fp3).

Verifier (add.tri): statement preparation 3 ms, the step 7 ms (≈ 6,000
permutations, Merkle checks batched), the three deferred claims 2.5 ms,
the decider 5.5 ms.

## 4. soundness tests

- circuit: an honest recorded run satisfies every row constraint and its
  memory closes; tampered gate, decomposition, permutation cells are
  refused; a failed assertion is refused unless `live = 0`; two runs on
  different data have the same key (`recursion::circuit::tests`);
- generic arithmetic equals lens's reference (`recursion::gm::tests`);
  words open and refuse a wrong symbol, index or sibling
  (`recursion::word::tests`); the circuit's permutation rows compute
  hemera (`circuit::air::tests`);
- one-step proof: verifies; a wrong output, input or cycle count, a
  tampered column value, deferred line, key value, opened symbol, carried
  claim, carried accumulator, chain or segment count are refused;
  two-step proof (`verify(verify(π))`): the same
  (`tests/recursion.rs`, 238 s);
- **bit-flip scan** of a full recursive proof: add.tri, rate 1/16: **284,382 bytes, 2,275,056
flips, 2,273,118 decoded, 0 accepted** (4,864 s on 16 threads, niced,
load 60–97; `rs/examples/ivc_flip`).

## 5. against the gates

| gate | measured | verdict |
|---|---|---|
| proof bytes flat in the run's length | 33 cycles 284,382 · merkle-32 282,814 · 16,383 cycles 282,206 · 1,572,850 cycles 284,446 | **met** (constant) |
| ≤ 64 KB | 284 KB (rate 1/16), 234 KB (rate 1/64) | **missed** (×3.6–4.4) |
| verify ≤ 1 ms | 17.9–38 ms (rate 1/16), 14.4 ms prepared (rate 1/64), under load | **missed** |
| a ≥ 10^6-cycle run proves | rec-16, 1,572,850 cycles, 121 steps, verifies | **met** |
| prover time per segment | 31.5 s a 2^15-row step over 121 steps (decider included), 28–46 s single steps; decider 60–100 s once | measured |
| bit-flip scan of a full recursive proof: 0 accepted | 2,275,056 flips, 0 accepted | **met** |
| `verify(verify(π))` at depth 2 | two-step proof: step 1's circuit verifies step 0's proof; accepted, tampering refused | **met** (IVC over the verifier) |
| every ledger row ≥ 128 | rates 1/16 and 1/64 (`params::tests`) | **met**; the IVC composition row is conjectured (`soundness.md`) |

## 6. what is left, and the gap to ≤ 64 KB / ≤ 1 ms

Where the bytes are (rate 1/16): the accumulation step's openings 140 KB
(4 words × 53 spot checks, deduplicated paths of 21 levels), the decider
104 KB (WHIR over an Fp3 word of ℓ = 21), the step's AIR messages 21 KB
(192 columns at ρ and at its successor, 138 publics, zerocheck, folds),
the state 18 KB. Levers measured or derived:

| lever | effect | status |
|---|---|---|
| rate 1/64 | 284 → 234 KB, verify 14 ms | measured; memory ×4 |
| query grinding 24 → 30 | t 53 → 50 (rate 1/16), 36 → 33 (1/64): −6 % of the openings | derived (`params::levers`) |
| decider folding factor 5 | decider rounds 4 → 3 | derived; changes the words' leaf layout |
| a wrap step (prove the final verifier with one non-accumulating proof of a small circuit) | replaces state + step + openings + decider by one WHIR opening of a ~2^20-cell word (≈ 60–90 KB at these parameters) | **not built**: needs the decider (lens WHIR, byte transcript) and the nox constraint evaluation (`Machine::eval`, a black box here) inside a circuit |
| the deferred constraint point (12.7 KB) committed instead of carried | −12 KB | not built |

The 64 KB goal is not reachable by parameters alone: the final proof
carries one accumulation step over four words and one WHIR opening, each
already above 64 KB at 128 bits. It needs the wrap step, whose blockers
are (1) the decider as a relation — lens's WHIR verifier hashes bytes;
a field-native WHIR (the transcript and tree of this package) would make
it a circuit of the same kind as the accumulation verifier — and (2) the
final deferred checks: the nox constraints are evaluated natively through
`Machine::eval`; in a circuit they need the machine's constraints written
over `Ops` (the per-opcode tables, owned by the opcode-coverage package).

Verify time: the native step verifier hashes ≈ 6,000 permutations (Merkle
checks batched 16-wide), the decider ≈ 5 ms, the statement-side
preparation 3 ms. ≤ 1 ms needs the wrap step's single small opening.

Other open items:

- an envelope profile and a CLI path for recursive proofs (joy);
- the prover: 21 s of a step is the accumulation (Fp3 accumulator commit
  8 s, query grinding 7 s, claim sumcheck 5 s), unoptimised;
- no external review of the circuit's constraint system; the tests check
  it against the native verifier and tampering, not exhaustively;
- composition with the opcode-coverage package: the step relation takes
  the machine's widths and constraint count from `machine::layout` and
  `Machine`; new opcodes enlarge `G`'s point only if they add columns
  (a word holds 64 columns; nox phase 2 shares word b with the circuit's
  49 phase-1 columns, so `W2` may not exceed 15).
