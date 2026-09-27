# Bounded execution with replaceable proof backends

Release repair contract authorized by the owner, 2026-09-11.

Zheng derives the global CCS, witness coordinates and public bindings from the
canonical program and public subject shape. A backend receives that derived
relation; the verifier never trusts matrices or a program digest from the prover.
The public direct certificate and native private proof have distinct formats and
disclosure contracts. Joy uses nox, Zheng and authenticated cyber state. Trisha
owns execution and proving for Triton and Neptune independently.

Pattern 16 accepts an atom witness. Its tag must be an atom and its check formula
runs on `[witness, object]`; the returned atom must equal zero. Each active call
consumes one prover input in native evaluation order. Inactive calls consume none.
The honest prover rejects exhausted and excess witness streams. Witness values
and intermediate columns remain secret-shared in the private proof. The public
statement contains no secret witness stream.

Branch selectors are constrained booleans. Each child activity is its parent
activity multiplied by the selected-arm bit. Inverse validity, word ranges and
call-check success are required only on the active path; arithmetic and copy
relations remain constrained everywhere. Different output tree shapes and dynamic
continuations still require further symbolic execution support.

`PrivateStatement` wraps public program, inputs, outputs, cycles and budget.
`prepare()` returns only the verifier-derived relation and sorted public wire
coordinates. `prepare_execution()` additionally computes a private witness on the
prover. Stable transcript bytes use a separate private-execution domain.

`execution::zk` proves the derived relation with native three-party arithmetic
MPC-in-the-head over Goldilocks and Hemera. Its circuit checks every CCS row,
column zero equal to one and every public coordinate. Each of 219 repetitions
uses fresh OS randomness. All three committed views and output-share vectors
are transcript-bound before Fiat–Shamir chooses the two opened views. The
verifier reconstructs the complete first messages and rechecks every challenge.

Protocol `zheng-ccs-mith-goldilocks-v1` has linear proof and verification costs.
Its interactive error bound is `(2/3)^219 < 2^-128`; the noninteractive protocol
also relies on the random-oracle and Hemera assumptions. The native implementation
and its symbolic nox relation have no independent production-security audit.
See [the complete private protocol](native-private-ccs.md) for encoding, allocation
bounds and disclosure. This protocol is separate from the legacy Spartan folding
proof; full dynamic nox coverage and recursive execution remain future work.

State certificates must bind the program's actual namespace, key, value and all
four root limbs. An unlinked query proof or native rerun cannot supply that binding.
Public state evidence may disclose consumed public dimensions. Private state
queries require their authentication inside the proved relation; public
state evidence must not be advertised as hiding query addresses or values.

## Public state format v1

`StateStatement` binds the execution statement, canonical four-limb state root,
root-in-subject ABI flag, and one ordered record per statically compiled lookup.
Activity is pinned for every record. Active records additionally pin namespace,
index, returned value and every root limb to the exact lookup wires. Inactive
records use a canonical zero payload and supply no cell evidence. The verifier
requires exactly the derived record count; namespace is in 0..9.

The state owner authenticates complete public dimension tables under versioned
systematic Lens commitments and checks their ordered 14-leaf Hemera root. Only
then may its cell accessor supply expected values to Zheng's state verifier.
This is public execution: no secret input is accepted, all proof columns and
queried dimension tables are disclosed. The API callback is an authentication
boundary, not a proof supplied by the prover. Joy embeds and validates the
certificate before calling the state verifier. All file/wire formats are bounded.

## Private queries over authenticated public state

A private-state backend may authenticate complete public dimension tables first,
then derive the CCS from the canonical program, public shape, expected root and
those exact tables. Each look constrains the namespace and index selector inside
the CCS, selects exactly one committed cell on an active path, equates the value
to that cell, and equates all four actual root limbs to the expected root. The
private witness contains the query coordinates; they are not separate public
lookup records. Thus external verification authenticates only public tables,
while the native private proof authenticates the actual hidden read and computation.

The first bounded implementation requires all ten public namespaces and at most
2048 total table fields, with the existing 32768 gate/row limit. Tables are public;
this does not disclose private BBG dimensions or implement hidden database state.
Table contents, metadata and root are checked before verifier relation derivation.
The native private backend hides query and witness columns under its protocol
assumptions. Its proof-size admission bound also applies. Public output and
reduction count can disclose information about the selected read or branch.
