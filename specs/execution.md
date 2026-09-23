# Public execution certificates

Implemented development protocol: `zheng-nox-public-execution-v2`.
The owner authorized execution/output binding on 2026-09-11.

## Statement and relation

`ExecutionStatement` contains a flat canonical nox program, public input
atoms, output atoms, reduction count and budget. The verifier derives the
subject shape from input length in Joy reverse-cons order with trailing zero,
and derives a global CCS from the public program. Constants reference wire 0.
Operands, intermediate values and output coordinates share global indices.
Matrices depend on the program and subject shape, never witness values.

The prover supplies a direct Spartan proof with a `PublicTensor` commitment
and a complete authenticated evaluation table. The verifier fixes dimensions,
sumcheck degrees, zero error and protocol/transcript domains. It authenticates
all columns and then checks **every CCS row exactly**, constant wire 0=1, and
all public input/output/cost coordinates against that same table. It accepts
neither a prover-defined relation/error vector nor an unchecked fold.

The transcript binds the canonical statement, dimensions, full relation and
public coordinate mapping. Program terms use tagged flat prefix encoding;
integers are little-endian u64. Public vector limits apply during deserialization.

The verifier does not invoke native nox, generate a witness, or accept a
trace from another computation. Prover-side native execution independently
checks output and cost agreement but is not the verifier's security boundary.
A newly generated certificate for another input or result cannot satisfy
verification against the original statement.

## Supported nox surface

| Tags | Semantics |
|---|---|
| 0 | static axis traversal; axis0 structural digest |
| 1–3 | quote, compose with static continuation, cons |
| 4 | constrained conditional selector and fixed-shape output |
| 5–8 | field add/sub/mul/inverse |
| 9–10 | structural digest equality and canonical 64-bit less-than, nox zero=true |
| 11–14 | canonical 32-bit XOR/AND/NOT/variable left shift |
| 15 | full structural Hemera hashing and final permutation |

Private backends support atom call witnesses (16), with checked continuation.
State backends authenticate lookups (17), including private query selection over
complete public tables. Direct public stateless proving accepts no secret stream
or unauthenticated lookup. See [backend contract](ccs-execution-backends.md).

Dynamic continuation formulas and differently shaped branch outputs remain
unsupported. Activity gates inverse validity, word ranges and call success;
inactive errors do not reject a successful selected path. The public budget must cover
the authenticated cost of the selected path, not an unselected expensive branch.
The relation bounds every possible cost below the field modulus, so its cost
wire cannot wrap; canonical public cycles are bound to that wire and must not
exceed the canonical budget. Native nox falls back to sequential budget threading
when static child reservations do not fit. Public cycles can reveal branch-cost
information even when the execution witness is private.

Limits: 64 public inputs, 4096 program/symbolic noun nodes, 128 depth, 4096 symbolic
calls, 32768 gates/rows (checked before constructing sparse matrices), 4096 output
atoms. Hash round construction checks limits at permutation boundaries. The
generic direct wrapper also caps matrix dimensions and total sparse entries.

## Disclosure, complexity and assurance

This is a full public algebraic witness certificate. It reveals every witness
element and has linear verification/storage cost; it is not a succinct or
zero-knowledge proof. Secret input and state requests are refused. No silent
fallback to the legacy trace-statement format occurs.

`PublicTensor` checks all raw columns under a domain-separated Merkle root.
Binding needs no expander distance, injectivity or sampling assumption. Exact
CCS checking also removes small-field sumcheck error as a basis for accepting
the execution relation. Spartan remains a checked consistency transcript; its
Goldilocks challenges alone must not be advertised as 128-bit soundness.
See `lens/specs/public-tensor.md` for the commitment contract.

This establishes the stated bounded relation, not a formal proof of the
symbolic compiler's implementation or a reviewed production/private protocol.
The separate Trisha backend proves the same verifier-derived relation using
Triton7's randomized STARK, with every row and public coordinate asserted by a
regenerated VM checker. Its distinct Joy format is `joy-nox-ccs-triton7-zk-v3`.
This does not assert that Hemera's novel permutation has independent review.

## Joy integration

Default stateless public `joy prove` and `Prover` use this format. Secret input
selects the private backend; explicit state files select authenticated state execution. Proof-mode `--claim` and
`--input-values` compare verified values. `--proof` also binds the supplied
program; self-contained verification uses the canonical embedded program.
`--budget` is an upper limit on the certificate's declared budget.

`ExecutionArtifact` has a distinct `JOYEXEC2` header and canonical postcard
payload, capped at 32 MiB; trailing bytes and malformed new artifacts fail.
Legacy artifacts require `--legacy-trace-statement` and refuse IO/state/secret
constraints. Legacy library methods remain explicitly statement-only.

Tests compare native nox with symbolic witnesses, include real compiled
Trident imports/loops/branches, mutate intermediate/hash/bit witnesses and
public claims, construct malicious proofs bypassing the honest prover, and
verify through fresh CLI processes. See audit/public-execution.md
for historical measurements. Current state acceptance tests exercise the new
protocol; obsolete recursive-opening requests remain rejected.
