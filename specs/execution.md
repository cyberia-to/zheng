# Public execution certificates

Implemented development protocol: `zheng-nox-public-execution-v1`.
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
| 9–10 | atom equality and canonical 64-bit less-than, nox zero=true |
| 11–14 | canonical 32-bit XOR/AND/NOT/variable left shift |
| 15 | full structural Hemera hashing and final permutation |

Dynamic continuation formulas, pair equality, differently shaped branch
outputs, calls (16) and state lookups (17) are rejected. Both branch arms must
be defined: inactive inverse-of-zero or invalid word operands conservatively
reject some otherwise successful nox programs. The public budget must cover
the static maximum path cost, including nox reservation rules; actual selected
path cost is separately constrained and authenticated.

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
A future succinct/ZK backend must preserve the same public relation and add
its own reviewed hiding and soundness construction.

## Joy integration

Default `joy prove` and `Prover` use the new format. Proof-mode `--claim` and
`--input-values` compare verified values. `--proof` also binds the supplied
program; self-contained verification uses the canonical embedded program.
`--budget` is an upper limit on the certificate's declared budget.

`ExecutionArtifact` has a distinct `JOYEXEC1` header and canonical postcard
payload, capped at 32 MiB; trailing bytes and malformed new artifacts fail.
Legacy artifacts require `--legacy-trace-statement` and refuse IO/state/secret
constraints. Legacy library methods remain explicitly statement-only.

Tests compare native nox with symbolic witnesses, include real compiled
Trident imports/loops/branches, mutate intermediate/hash/bit witnesses and
public claims, construct malicious proofs bypassing the honest prover, and
verify through fresh CLI processes. See docs/explanation/public-execution.md
for actual measurements and remaining legacy acceptance failures.
