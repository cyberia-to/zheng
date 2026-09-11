# Authenticated execution release requirements

Status: release blocked; findings and implementation requirements from the
2026-09-11 Trident/Warrior audit. The wire repair is implemented separately;
this document does not claim the proof foundations below are implemented.

## Confirmed format regression

Lens Brakedown now emits `Opening::TensorMerkle` (`lens/brakedown/src/lib.rs`).
The former zheng wire adapter accepted only `Tensor`, preventing Joy from
saving valid in-memory decider proofs. The repaired adapter preserves the
complete authenticated opening; legacy unauthenticated variants are rejected.

The recursive helpers `ccs/verifier_steps.rs` and `ccs/transcript.rs` still
encode the retired `Tensor` protocol and return empty witnesses for a
`TensorMerkle`. `commit` now refuses axis/look opening inputs explicitly with
`UnsupportedRecursiveOpening`. This is a safety boundary, not completed
recursive support. Existing positive axis/look acceptance tests remain
unfulfilled and must pass again before the requested release.

## Independently traced existing limitations

These are documented in `specs/decider.md` under soundness; they predate the
format regression and this audit. No exploit was added as part of this work.

- `lib.rs::verify` derives the universal/eq instances and checks the linear
  group's zero error, then calls `spartan::verifier::SpartanVerifier::verify`.
  It does not replay or verify a fold transcript. Its comment explicitly
  says universal errors can contain honest nonlinear cross terms.
- `folding/fold.rs::fold_step` checks incoming witnesses on the prover side.
  `fold_step_inner` recomputes the folded error from the folded witness.
  A verifier must authenticate this transition, not trust the prover gate.
- `folding/decide.rs::decide` absorbs Statement and accumulator metadata in
  Fiat–Shamir. `SpartanVerifier` checks a relaxed CCS relation and the PCS
  evaluation. Statement absorption prevents transcript substitution; it does
  not prove that a witness executes the named program with the named inputs.
- `folding/fold.rs` already contains tests documenting the unpinned constant
  wire and a satisfying witness unrelated to Statement. `types.rs` private
  accumulator fields protect the Rust construction API, not a cryptographic
  verifier processing wire data from another implementation.
- `lib.rs::commit` checks first/last row hashes and budget on the prover side.
  The public verifier has no authenticated first/last trace openings.
- Joy's output metadata contains field values, but Statement.output_hash is
  the hash of the final trace row containing arena identifiers. Therefore
  metadata values cannot be called verified outputs. Joy now refuses proof
  output claims and labels metadata unverified; execution claims still work.

## Required proof architecture

1. Define public and private witness inputs explicitly, with a verifier-pinned
   constant wire and program/input/output/state/budget boundary commitments.
2. Prove the fold transitions (including nonlinear cross terms) using a
   verifier-checked accumulation protocol. Fiat–Shamir over the final
   accumulator alone is insufficient.
3. Authenticate data movement between trace rows and between synthetic
   arithmetic/hash gadgets: a copy/permutation relation or an equivalent
   commitment-opening construction. Equal native values placed into separate
   witnesses are not by themselves an authenticated connection.
4. Implement TensorMerkle opening constraints: canonical field decoding,
   row-combination evaluation, expander-code relation, queried-column dot
   products, indexed leaf hashes, Merkle path orientation/root authentication,
   and query indices derived from the authenticated transcript.
5. Connect axis/look commitment, point, value, and state root to the same
   checked trace relation. Preserve authentication data in the wire.
6. Prove the result arena-node/tree relation and flattening into emitted
   outputs, plus the public-input subject relation. Only then restore
   `ProofData.claim` verification and proof-mode `--claim`.

## Acceptance criteria

- Fresh Trident -> Joy compile/run/prove/disk/verify with public input,
  secret input, hashing, and compiled state reads on the live state root.
- Reject changed public inputs, output values, program, budget, state root,
  column bytes, Merkle siblings/orientation, query index, point and value.
- Existing documented constant-wire/unrelated-statement residual tests must
  become rejection tests under the final public verifier.
- No prover-only native check or self-equality substitutes for the relation.
- Measure actual proof size and runtime. Authenticated openings are larger
  than the retired ~1 KB decider artifacts; no old size claims carry over.
- Keep exhaustive bit-flip stress audits separate from bounded CI regressions
  and report explicitly which were executed. Do not call skipped audits green.
