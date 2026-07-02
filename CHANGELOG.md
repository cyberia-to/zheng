# Changelog

## [0.1.0] — unreleased

Initial minimal release: turn a [[nox]] execution trace into a verifiable proof.

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
