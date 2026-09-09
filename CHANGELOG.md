# Changelog

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
