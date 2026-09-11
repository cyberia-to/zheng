---
status: accepted
tags: zheng, soundness
---

# Direct execution proof review

Independent source review, 2026-09-11. This records implementation obligations;
it does not certify a protocol or claim they are already implemented.

The implementation adopted full-table PublicTensor authentication and exact
CCS row/public-coordinate checking. These replace the separate-coordinate
openings and empirical-code assumptions discussed in the initial review below.
The final contract is [execution.md](../execution.md); the review preserves why
the initial sampled PCS route was rejected for this certificate.

## Viable relation boundary

A verifier-derived, full execution CCS checked with a verifier-owned zero error
vector removes the existing unverified folding premise. The constant wire and
all public values must be authenticated under the same witness commitment.
Authenticating a statement only in Fiat–Shamir does not impose its values on
the witness. Separate PCS openings at verifier-known Boolean coordinates can
bind those coordinates, subject to the PCS assumptions below.

The verifier must derive the relation from public program semantics and public
capacities. Prover-selected constraints, a trace-specific native replay, and
independently equal values in disconnected witness slots do not establish the
execution relation. Explicitly reject unsupported patterns before proving.

## Required wrapper checks

- Pin witness length to the CCS column count padded as specified (currently
  Spartan pads to at least 64). Derive inner round count from that length;
  never derive the matrix width from a proof-controlled round count.
- Require positive power-of-two row count, matching sparse matrix shapes,
  in-range matrix columns and multiset indexes, and matching coefficient and
  multiset lengths. Require exactly one zero error per row.
- Bound outer sumcheck degree by maximum multiset degree plus one and inner
  degree by two. Require coefficient count to equal declared degree plus one.
  Current generic sumcheck verification performs neither degree check.
- Bind protocol version, deterministic instance identity, dimensions, statement,
  and each opening's coordinate/value into domain-separated transcripts.
  Encode transcript integers with a fixed width; existing round indexes use
  native `usize::to_le_bytes`, which differs across 32/64-bit targets.
- Bound proof dimensions before shifting/allocating. Validate every field-byte
  sequence has exact expected length and canonical Goldilocks representatives.
  Lens currently reduces field encodings and ignores partial trailing chunks.

Existing `SpartanVerifier` derives the witness dimension from the supplied
inner polynomial count and ignores sparse columns outside that dimension.
Existing `SumcheckVerifier` verifies round consistency but not degree bounds.
Both are unsafe assumptions for a new direct proof wrapper without validation.

## PCS restrictions

Use separate `Brakedown::verify` calls for coordinate openings. The current
`batch_verify` path for two or more points ignores the supplied point/value
claims, verifies a random point, and derives that point's claimed value from
the proof itself. It cannot authenticate the public coordinate claims.

Lens's 100-bit query target depends on an assumed minimum absolute codeword
weight of four, explicitly described in source as empirical. The encoder is
a single Margulis-style layer, not the recursively distance-amplified code of
the Brakedown construction. A local exact modular rank check found full rank
at input sizes 1, 2, 4, 8, 16, 32, 64 and 128. This check proves neither a
general injectivity theorem nor the assumed distance bound.

Sumcheck and batching challenges are single Goldilocks elements. Their
algebraic soundness cannot be described as 100/128-bit simply because the PCS
query target uses that number. State degree/size-dependent algebraic error
and the code-distance assumption separately; do not invent assurance bits.

## Privacy boundary

Current Spartan and TensorMerkle are deterministic and unmasked. Openings
disclose encoded witness columns and full row combinations; opening a Boolean
coordinate can disclose its entire containing row. A raw direct execution
proof must therefore be restricted to explicitly public witness execution.
Reject private inputs rather than silently disclosing them. A release that
supports secrets needs a reviewed hiding/ZK IOP and PCS construction covering
sumcheck messages, queried columns, coordinate openings, repeated proofs and
secret-dependent shape. Merkle salt alone does not supply this property.

## Adversarial acceptance tests

1. Make a fresh proof for an invalid witness (zero constant, wrong public input
   or output, altered control/arena link) while bypassing honest builder checks;
   the public verifier must reject it.
2. Remove inner rounds and construct a commitment to a smaller witness so
   omitted matrix columns cannot disappear from the checked relation.
3. Supply excessive-degree rounds, mismatched degree metadata, empty
   coefficient vectors, invalid dimensions and noncanonical field bytes.
4. Splice valid public-coordinate openings from another proof, reorder them,
   duplicate a coordinate or change the expected value; reject each case.
5. Change program, shape, state root, focus bound, public input and output
   independently. Reject unsupported patterns and secret proving explicitly.
6. Check positive outputs against the independent nox reducer, including
   nested composition/cons/branch and nontrivial public-input programs.

These tests target construction of malicious artifacts, in addition to
post-hoc byte mutations of proofs emitted by an honest prover.

## Implemented review checks

The direct execution path now uses `lens::brakedown::PublicTensor`, an explicit
public-data backend. It authenticates all raw columns, reconstructs the indexed
Merkle root, checks canonical paths and evaluates their complete row
combination. Its versioned commitment includes the variable count. This removes
the legacy Brakedown encoder-distance and matrix-proximity assumptions from
direct execution. It discloses the whole witness and has linear verification.
The verifier also retrieves that authenticated table, checks the complete CCS
exactly, and compares every pinned public coordinate including constant one.
This full algebraic witness certificate removes dependence on the probabilistic
Goldilocks sumcheck error for acceptance. Spartan consistency is retained, but
cannot make an invalid algebraic witness pass the deterministic checks.
The legacy Brakedown observations above remain relevant only to legacy callers.
See `lens/specs/public-tensor.md` for the exact contract.

`rs/tests/execution_adversarial.rs`: five tests pass against the new wrapper,
covering 64/128 witness dimensions, fresh alternative execution proofs, public
program/input/output/cost/budget binding, malformed dimensions and sumcheck
shapes, and malformed/reordered/duplicated openings. The independent review
found and implementation fixed the odd-variable row/column split reversal in
canonical opening validation. Direct-prover unit tests additionally construct
raw Spartan proofs bypassing the honest builder for zero-constant and invalid
witness attacks.

Symbolic branch compilation constrains both arms. A valid chosen arm with an
invalid inactive inverse therefore fails closed. The relation's regression
`unselected_invalid_inverse_is_conservatively_rejected` records this restricted
completeness boundary; successful proofs remain required to match nox.

## Primary protocol references

- [Spartan paper](https://eprint.iacr.org/2019/550) and the
  [authors' implementation](https://github.com/microsoft/Spartan). Its README
  documents fresh `OsRng`-seeded private `RandomTape` for each proof and the
  concrete implementation's discrete-log assumptions. Its ZK guarantees cannot
  be inferred for a different deterministic Merkle-based implementation merely
  from reuse of the Spartan name.
- [Brakedown paper](https://eprint.iacr.org/2021/1043). The implemented Lens
  construction must establish its own code and opening assumptions before
  inheriting concrete security claims. A distance claim for honest codewords
  also needs an argument covering adversarial committed matrices.

The author repository was read through browsing. Search resolved both paper
records; the browsing service could not fetch their full PDFs in this review.
