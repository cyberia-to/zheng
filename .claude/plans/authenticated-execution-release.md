# Authenticated execution release requirements

Status: execution-proof implementation authorized by the owner on 2026-09-11;
production release remains blocked until the stated gates pass. Findings from the
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

## Smallest implementation route (authorized; implementation in progress)

Recommendation: first prove the full, unfolded execution CCS with a public
input binding and a zero-knowledge IOP/PCS. Treat verifier-checked folding as
an optimization of that already-tested relation. Larger proofs are genuine
proofs if the verifier checks the actual relation; an accumulator receipt,
replay result, or proof of unrelated arithmetic is not an execution proof.

| Route | Reusable implementation | Additional obligations | Recommendation |
|---|---|---|---|
| Full unfolded CCS | sparse matrices, arbitrary-row outer/inner Spartan sumchecks, local arithmetic gadgets | complete VM relation, public binding, zero-error verification, hiding/ZK PCS/IOP | first correctness milestone |
| Verifier-checked folding | same complete VM relation plus existing fold arithmetic as reference | all full-CCS obligations plus sound cross-term/transition proof, recursive verifier, accumulation invariant, linkage | later size/runtime optimization |

The direct route removes the current unverified-fold premise; it does not
remove the VM relation or privacy work. Current `SpartanProver::prove` can
already handle arbitrary power-of-two matrix row counts. The direct verifier
must supply an all-zero error vector, never an error vector from the artifact.

### Concrete file and API boundaries

- `zheng/rs/src/execution/types.rs`: `ExecutionStatement` with canonical
  program identity, public input/output vectors (or circuit-checked hashes),
  state root, budget, and protocol version; `ExecutionShape` with bounded
  public capacities. Use a new proof type/format, not existing relaxed
  `TraceProof` masquerading as verified execution.
- `zheng/rs/src/execution/layout.rs`: one global witness vector with shared
  indices for repeated values; public prefix/constant, trace registers,
  invocation/control-flow records, arena nodes, hash round state and state
  opening witnesses. Layout and matrices derive solely from public shape and
  supported VM semantics, never from a prover-chosen trace or constraint list.
- `zheng/rs/src/execution/relation.rs`: deterministically assemble a sparse
  global CCS. Lift local gadget columns into global indices. Shared indices
  implement fixed copies; variable references need a constrained lookup/RAM
  relation (or a bounded one-hot multiplexer initially). This avoids a new
  permutation argument for fixed copies while preserving dynamic semantics.
- `zheng/rs/src/spartan/{prover,verifier}.rs`: direct `prove_execution` and
  `verify_execution` wrappers over the global relation with zero error.
  Validate dimensions/round counts against the public shape before allocating.
  Existing general relaxed APIs remain separate, explicitly named.
- `zheng/rs/src/execution/public.rs`: bind constant=1 and public coordinates
  under the SAME witness commitment using authenticated fixed-point openings
  with verifier-known positions/values. An alternative is a proper
  public/private polynomial split in the IOP. Choose and specify one;
  do not pin constants using another free witness column. The current Lens
  multi-point `batch_open` path must not be assumed to bind arbitrary supplied
  point/value pairs; use individually checked openings until a batching proof
  is specified and tested. Privacy changes below apply to these openings too.
- `nox/rs/trace.rs` and `reduce.rs`: an optional proof-witness collector records
  invocation IDs, parent/child roles, entry/return linkage, allocated/read arena
  nodes and multi-row boundaries. `Tracer::record(TraceRow)` alone supplies no
  parent/child relationship. Keep ordinary execution tracing compatible.
- `nox/rs/data/reduction.rs`: expose a bounded prover-local witness view via
  existing `count/get` or a narrow iterator. Do not serialize the arena or
  secret call responses into the public artifact.
- `zheng/rs/src/execution/{arena,control,patterns}.rs`: constrain formula
  decoding, object/result nodes, child calls, dynamic compose continuation,
  branch selection, call check, budget transitions and halt/padding.
  Existing `universal.rs` is a source of local arithmetic gates, not a complete
  nox machine relation: compose/cons have no local constraints, and arena IDs
  must be tied to atom/pair contents. Review every supported pattern and all
  multi-row bit/inverse/hash chains against current nox code, not old spec
  register tables.
- `zheng/rs/src/execution/{tensor_merkle,hash}.rs`: constrained TensorMerkle
  authentication and field/canonicality checks connected to the global
  witness, including transcript queries and state-root membership. Each hash
  input/output shares actual global variables with its caller; native
  recomputation is witness generation only.
- `joy/rs`: build the private execution witness while the arena is alive;
  carry public values in `ExecutionStatement`; restore claim verification
  only for the new execution proof type. Compile/run interface remains stable.

### Privacy is required in both routes

The existing Spartan prover has no randomness/blinding argument, commits raw
`CCSWitness.z`, and emits deterministic sumcheck messages. Lens TensorMerkle
emits explicit row combinations and queried encoded-witness columns
(`lens/brakedown/src/lib.rs::open`). Neither path contains a zero-knowledge
masking layer. Therefore using an unfolded private trace with the current PCS
would disclose witness-dependent data; removing `folded_witness` from serde
is not a zero-knowledge construction.

Add an explicit, reviewed hiding/ZK IOP+PCS protocol and cryptographic prover
randomness before private-input execution is accepted. The design must cover
sumcheck messages, column queries, public-coordinate openings and repeated
proofs, not merely salt the Merkle root. Keep the trace, secret inputs and
arena on the prover side. Public capacities/padding must be fixed independently
of secret control flow unless trace length is deliberately part of the public
statement. The Lens code-distance assumption also needs a stated assurance
level; current query counts depend on an empirical distance floor. These are
protocol prerequisites, not cosmetic release flags.

### Bounded implementation sequence and gates

1. Freeze `ExecutionStatement`, public dimensions, privacy requirements and
   exact supported nox semantics; record the new proof format and assurance
   assumptions. Do not inherit old proof size/security claims.
2. Implement global layout/public binding and prove small directly-built CCS
   relations with the verifier's zero error; test constant/public-input
   enforcement and dimension validation independently of the prover builder.
3. Build and test the complete control/arena/pattern relation against nox.
   Use private witness mutation regression tests at the relation boundary;
   each invalid relation must fail the public proof verifier.
4. Implement/review the masking protocol and authenticated state gadgets.
   Review no raw secret/arena serialization and explicit disclosure boundaries.
5. Restore end-to-end compiled public/secret/hash/state flows and output claims
   only when soundness, privacy and negative acceptance checks all pass.
6. Benchmark increasing public capacities. Current Brakedown query count grows
   with matrix width, so the direct route may have substantial proof size and
   memory costs. Report actual measured bounds; optimize folding afterward.

A useful minimal vertical slice is a complete bounded execution relation for
one explicitly listed program family, but it is a development milestone. It
must not be shipped as complete nox support while other advertised language
features lack execution constraints.

## Implemented public execution checkpoint

2026-09-11: owner authorized closing execution/output linkage. New
execution module derives a global CCS from the canonical program, supports
bounded public nox tags0–15, and binds inputs/output/cost/budget. The public
format authenticates the full witness using Lens PublicTensor and checks all
CCS rows exactly, plus Spartan consistency. This removes unchecked folding,
unpinned constants, empirical code-distance and small-field sumcheck error
from acceptance of this public certificate. Witness disclosure and linear
verification are explicit; secret calls/state remain refused. Default Joy
prove/verify/traits use the new format, legacy inspection requires opt-in.
Contract: specs/execution.md; evidence: docs/explanation/public-execution.md.
Succinct/ZK proving, dynamic control/shape completeness and authenticated
state execution remain future protocol work, not completed by this checkpoint.
