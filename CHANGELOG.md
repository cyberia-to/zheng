# Changelog

## [0.3.3] — 2026-09-09

### Added

- `Accumulator::blank(&CCSInstance)` — the public way to start a fold
  outside `commit()`. 0.3.2 made the fields `pub(crate)` and left
  downstream provers that fold their own universal-step rows (foculus:
  tip, tickets, pay) with no constructor at all. The gate is unchanged:
  every step still passes `fold`'s satisfiability check, and `verify`
  derives the instance from the group's position, never from the
  accumulator. `commit()`'s own blank accumulator now uses the same
  constructor. No wire change.

## [0.3.2] — 2026-09-09

### Fixed

- **soundness: `fold_step` folded any witness unconditionally.** An
  empirical attack — build a witness with the right shape but a wrong
  register (e.g. an add row claiming `5 + 3 = 9`), fold it through the
  PUBLIC `fold_step`/`fold` entry point, decide, verify — succeeded before
  this fix: `fold_step` trusted the caller to have screened the witness,
  and the only screen was `commit()`'s own separate, caller-side gate
  (`CommitError::StepUnsatisfied`). Any caller reaching `fold_step`/`fold`
  directly — a downstream crate, a future bug in some other caller — could
  skip it entirely. The per-witness satisfiability check now lives in
  `fold_step` itself (new `FoldError::UnsatisfyingWitness`), and
  `Accumulator`'s fields are `pub(crate)` (were `pub`): the type can only
  be produced by folding through this gate, not by a bare struct literal
  from outside the crate. `cli` gains `Accumulator::witness_commitment()`
  / `::step_count()` read accessors for the one place it read a field
  directly.
- **is this a real soundness hole in shipped 0.3.0/0.3.1? Yes, and no
  proof is retroactively affected.** A proof HONESTLY produced by
  `commit()` from a real nox trace was never at risk: `commit()`'s own
  gates already ensured every folded witness was a genuine, satisfying
  encoding of that trace before `fold_step` ever saw it. What was true,
  and is now closed, is that `fold_step`/`fold` — the lower-level public
  API `commit()` is built on — offered NO defense of its own: a party
  with the ability to call them directly (bypassing `commit()`) could
  fold an arbitrary, non-satisfying witness and still get a `decide()`/
  `verify()`-accepting proof for any `Statement`. If you have proofs from
  0.3.0/0.3.1 produced via `commit()`, they remain valid; this closes what
  a malicious prover calling the folding API directly could get away with
  going forward.

### Found, not closed (see `specs/decider.md` §soundness for full detail)

- **the universal instance's constant wire (`z[32]`) is never
  independently pinned.** The all-zero witness satisfies the ENTIRE
  universal CCS exactly — not merely undetected, genuinely zero error —
  because every row that treats `z[32]` as "the literal 1" is itself
  gated by a selector that is also a free witness column. This fix's
  per-witness gate cannot catch it: the witness is not lying about its
  own error. Closing it needs a public/private witness split or an extra
  fixed-point PCS opening of `z[32]` checked against 1 — an architecture
  change, sized comparably to the universal-step-CCS milestone, not
  attempted here. `commit()`'s honest path is unaffected (it always sets
  `z[32] = 1`).
- **a genuinely satisfying but semantically meaningless witness still
  verifies against any Statement.** Unchanged from 0.3.0: `decide()`'s
  SuperSpartan sumcheck proves "the error is consistent with the
  committed witness", not "the witness is a real nox execution, or
  related to the Statement". Closing this needs a verifier-checked fold
  over the real steps that produced the witness (the recursion
  milestone) — not achievable in this fix.

### Added

- Three regression tests documenting the attacks above precisely —
  `fold_step_rejects_witness_with_wrong_register` (closed),
  `attack_zeroed_constant_wire_satisfies_universal_instance` (open,
  documents the constant-wire residual),
  `attack_satisfying_but_meaningless_witness_passes_for_any_statement`
  (open, documents the recursion-milestone residual) — all in
  `rs/src/folding/fold.rs`. A fourth, `fold_all_rejects_unsatisfied_eq_step`
  (`rs/src/lib.rs`), pins the same fold-time gate for the degree-1
  binding path, which previously relied solely on `verify()`'s zero-error
  rule to catch a step folded past `commit()`'s own gate.

No wire format change — `Accumulator`'s serialized shape (`witness_commitment`,
`error_evals`, `step_count`) is unchanged; only Rust-level field visibility
and a new `FoldError` variant.

## [0.3.1] — 2026-09-09

### Fixed

- **wire form: inert bytes off the proof.** A single-bit-flip scan of a
  0.3.0 artifact found 2 080 proof bytes a flip could not disturb: the
  8-byte codeword symbols in `Opening::Tensor::query_responses` (20
  queries × log n rounds × 8 B per group). Root cause is in lens, and
  pre-existing since lens dbf472b (2026-04-16, long before zheng 0.2.2):
  `Brakedown::verify` reads each query's index (it must equal the
  transcript-derived one) and never its symbol — the commitment is a flat
  hemera hash of the whole codeword, so a symbol cannot be authenticated
  against it and the verifier does not try. **Inert bytes, not a
  soundness hole in the sense of the verifier accepting a different
  proof**: the verification predicate never depended on those bytes, so a
  flipped symbol verified for the same reason an absent one would. (The
  fact that the proximity queries carry no checked symbol IS a gap in the
  lens Brakedown verifier — its opening binds `round_commitments[0]` to
  the commitment, replays the query indices and compares `final_poly` to
  the claimed value, nothing more — recorded in specs/decider.md and
  owed to lens, not patched here.)
- `Proof.pcs_opening` now serializes through `zheng::wire::opening`:
  round commitments, final polynomial and the query indices (u32) only;
  deserialization restores the opening with empty symbols, exactly what
  the verifier reads. Every byte of a serialized `TraceProof` is now
  verifier-checked: `every_bit_of_the_wire_is_checked` flips every bit
  of every byte of a one-group proof, `every_byte_of_a_two_group_wire_is_checked`
  bits 0 and 7 of every byte of a hash proof — each flip fails to
  deserialize or fails to verify.
- Proof bytes (joy, postcard, proof only): hello 1127 B (was 2388),
  two-divine 1179 B (2440), one hash 2154 B (4496), Merkle-32 2161 B
  (4503). Artifacts: 1312 / 1384 / 2389 / 2581 B. Wire-incompatible with
  0.3.0 artifacts.

## [0.3.0] — 2026-09-09

### Changed

- **BREAKING (transcript + proof format): the universal step CCS** (#8,
  step 2; specs/constraints.md). ONE CCS instance for every Layer-1 row:
  18 one-hot pattern selectors `s_p` bound to r0 (`s_p·(r0−p) = 0`,
  `Σ s_p = 1`), 25 one-hot round selectors `u_k` bound to r14 with
  `Σ u_k = s_15`, derived flags π/κ and the Poseidon2 round constant as a
  witness column `rc = Σ RC_j·u_j` — one instance for all 25 rows of a
  hash block instead of one per constant set. Each pattern's constraints
  are multiplied by their gate (degree +1; Lagrange selectors over 18
  values would have been +17). m = 64 rows, 15 matrices, degree ≤ 4,
  witness 96 → 128. Fiat-Shamir transcript replays and BBG root chains are
  universal rows too.
- `TraceProof` is `{ universal: ProofGroup, binding: Option<ProofGroup> }`
  — two accumulator groups at most for any program. `ProofGroup { proof,
  accumulator }`. The verifier derives each group's instance from its
  position (`ccs::universal_ccs()`, `ccs::eq_instance()`); the instance
  is no longer on the wire (`Accumulator.committed_instance` is
  `serde(skip)`), closing the hole where a proof could name a trivial
  instance for itself.
- `commit()` gates every universal row at commit time:
  `CommitError::StepUnsatisfied(t)` for an unknown tag, an out-of-range
  hash round or a register file violating its pattern. The verifier
  cannot see a violated Layer-1 row through the relaxed fold (the error
  vector of a degree-4 instance is legitimately non-zero); the zero-error
  rule keeps guarding the degree-1 binding group.
- Pattern encodings verified against real nox traces for the whole family
  (add, sub, mul, eq, branch, inv, lt, xor, and, not, shl, call). inv (8)
  now checks the final-row inverse `r6·(r6·r4 − 1) = 0` (its old
  `r5_{t+1}·r3_t = 1` never held on a real trace). lt/xor/and gained bit
  booleanity, not gained `r11 = 0`.
- `ccs::patterns` (per-pattern instances), `particle::partial_round_ccs`,
  `trivial_hash_ccs`, `Z_LEN_HASH`, `build_ccs_from_trace`,
  `build_hash_steps_from_trace` removed; `build_universal_steps_from_trace`,
  `universal_witness`, `poseidon_witness`, `eq_instance` added.
  `build_look_steps_from_trace` returns `(eq steps, universal rows)`.
- Downstream: joy pins `zheng = "0.3.0"`, bbg `"0.3"`.

### Measured (joy, real programs; proof bytes in postcard, artifact = proof + statement + meta)

| program | 0.2.1 | 0.2.2 (structures) | 0.3.0 proof | 0.3.0 artifact |
|---|---|---|---|---|
| hello `(a+b)*a` | 3 groups / 5.4 KB | 2 / 3623 B | 1 / 2388 B | 2578 B |
| two `divine()` | 12 / 20 KB | 5 / 8525 B | 1 / 2440 B | 2697 B |
| one `hash` | 23 / 52 KB | 22 / 50204 B | 2 / 4496 B | 4801 B |
| Merkle-32 (33 hashes, 1906 reductions) | 1343 / 2.67 MB | 22 / 56886 B | 2 / 4503 B | 11176 B (6523 B of it is joy's `meta.assembly`) |

Proof size is now a constant of the system (~2.4 KiB + ~1.7 KiB when the
program opens anything). Every proof made before this change fails
verification.

## [0.2.2] — 2026-09-09

### Fixed

- **proof size — accumulator groups are structures, not runs** (#8, step 1):
  `commit()` now partitions steps by exact `CCSInstance` equality across
  the whole trace (first-occurrence order) instead of opening a new
  accumulator at every structure switch along the trace. Group count is
  bounded by the number of distinct instances, never by trace length.
  Measured with joy: hello 3→2 groups (5.4 KB→3.6 KB), two-divine 12→5
  (20 KB→8.5 KB), one hash 23→22 (52 KB→50 KB), depth-32 Merkle path
  1343→22 (2.67 MB→57 KB). Soundness unchanged: linkage digest over every
  group, zero-error rule for degree-1 groups, commit-time gates. Not a
  wire-format change — verify recomputes the linkage from the proof's own
  groups. Step 2 (the universal step CCS) lands as 0.3.0.

## [0.1.0] — unreleased

Initial minimal release: turn a [[nox]] execution trace into a verifiable proof.

### Changed

- **transcript format break**: `Statement` gained `bbg_root: [u8; 32]` (the
  BBG state root for look/pattern-17 reads; `[0u8; 32]` = no state read) and
  `absorb_statement` now absorbs it after `focus_bound`. Every proof made
  before this change fails verification against the new transcript. The
  accumulator-size stabilisation (soft3 blocker 3) was out of scope for this
  change, so the format may break once more when that lands.

### Added

- SuperSpartan IOP over CCS (Customizable Constraint Systems) — outer + inner
  sumchecks, arbitrary-degree AIR constraints
- Brakedown multilinear PCS via `lens` (expander-graph codes, transparent,
  post-quantum) — one commitment, one opening per proof
- sumcheck protocol — O(N) prover, log(N) rounds
- HyperNova folding — cross-term, β-challenge, per-CCS-structure accumulators
- CCS encoding of nox patterns (`ccs/patterns.rs`), Poseidon2 particle
  constraints (`ccs/particle.rs`), Fiat-Shamir transcript replay as Poseidon2
  CCS instances (`ccs/transcript.rs`)
- five entry points: `commit`, `open`, `verify` (`verify_eval`), `fold`, `decide`
- canonical workspace layout — `rs/` (library) + `cli/` (binary `zheng`)

### Security

- closed the Brakedown proximity Fiat-Shamir soundness gap: `transcript.squeeze()`
  is now proven by real Poseidon2 CCS constraints, replacing the `eq(0,0)` stubs
- BBG root-hash binding carries namespace + accumulator-commitment interface
  fields (`H(commit ‖ A ‖ N) == bbg_root` constraint pending BBG design for `A`)
