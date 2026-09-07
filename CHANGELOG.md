# Changelog

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
