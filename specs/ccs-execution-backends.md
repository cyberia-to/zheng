# Bounded execution with replaceable proof backends

Release repair contract authorized by the owner, 2026-09-11.

Zheng derives the global CCS, witness coordinates and public bindings from the
canonical program and public subject shape. A backend receives that derived
relation; the verifier never trusts matrices or a program digest from the prover.
The public direct certificate and the private Triton checker are distinct formats.

Pattern 16 accepts an atom witness. Its tag must be an atom and its check formula
runs on `[witness, object]`; the returned atom must equal zero. Each active call
consumes one prover input in native evaluation order. Inactive calls consume none.
The honest prover rejects exhausted and excess witness streams. Witness values
and intermediate columns are absent from the private statement and artifact.

Branch selectors are constrained booleans. Each child activity is its parent
activity multiplied by the selected-arm bit. Inverse validity, word ranges and
call-check success are required only on the active path; arithmetic and copy
relations remain constrained everywhere. Different output tree shapes and dynamic
continuations still require further symbolic execution support.

`PrivateStatement` wraps public program, inputs, outputs, cycles and budget.
`prepare()` returns only the verifier-derived relation and sorted public wire
coordinates. `prepare_execution()` additionally computes a private witness on the
prover. Stable transcript bytes use a separate private-execution domain.

The Trisha backend emits a deterministic Triton program that materializes every
column once, pins column 0 to one, pins public coordinates, and asserts every CCS
row. The verifier regenerates this entire checker and its native program digest.
Triton 7's default STARK proves the checker with fresh upstream ZK randomness.
The proof is explicitly a Triton backend of the Zheng relation, not the legacy
Spartan folding proof. Costs and supported-language limits must be reported as
measured; this bridge does not imply full nox VM coverage or recursive execution.

State certificates must bind the program's actual namespace, key, value and all
four root limbs. An unlinked query proof or native rerun cannot supply that binding.
Public state evidence may disclose consumed public dimensions. Private state
queries require their authentication inside the proved relation/checker; public
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
while the proved checker authenticates the actual hidden read and computation.

The first bounded implementation requires all ten public namespaces and at most
2048 total table fields, with the existing32768 gate/row limit. Tables are public;
this does not disclose private BBG dimensions or implement hidden database state.
Table contents, metadata and root are checked before verifier relation derivation.
The generated checker inherits Triton ZK for private query/witness columns.
