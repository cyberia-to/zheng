# Disclosed noun memory

Status: experimental component for the dynamic public certificate profile.

The verifier owns an append-only table of validated noun definitions. A table
index addresses one occurrence of a noun; its four-limb Hemera particle gives
its content identity. A definition consists of an atom or ordered pair of prior
indices, the claimed particle and the claimed cached Cost. The verifier checks
all three before admitting the definition. Construction starts with an empty
table. Every read resolves through this table, including the reads used for Cost
derivation. There is no constructor from an unchecked table or supplied root.

The compact `append_value` entry accepts only the atom or ordered prior indices
and derives particle and Cost internally. It uses the same admission rules and
validated storage as `append`. A transport can therefore omit redundant claimed
metadata. Public root bindings must still compare the derived particles with
the expected statement. Derived metadata is never a successful execution claim.

## Admission

Atoms are canonical Goldilocks u64 values below p. Particle limbs are canonical
field values. Atom identity hashes its eight little-endian bytes using native
Hemera leaf framing (counter zero, non-root); pair identity hashes the ordered
child particles using native Hemera parent framing (non-root). All four limbs
must equal the claimed identity. The implementation uses Hemera directly and
does not call the nox evaluator or accept a prover-supplied constraint system.

Both pair indices must be strictly less than the table length before insertion.
Self, forward and missing references reject. Every Cost read consequently
resolves to a previously validated record. Atom Cost is Exact(0). Pair Cost
follows the complete native 0..17 table and malformed-body rules specified in
[noun-cost-component.md](noun-cost-component.md). Arithmetic saturates in u64;
Cost values at or above the field modulus retain their full integer meaning.
Quoted data and unselected branch arms have the same metadata interpretation.
The claimed Dynamic selector and complete u64 value must equal this derivation.

Duplicate definitions are allowed and independently validated. Table indices
are never used as content equality. Equal structural nouns derive equal Costs;
identifying distinct structures by particle relies on Hemera collision
resistance. This component makes no separate global collision-detection claim.

## Bounds and reads

The caller supplies a maximum record count and a maximum requested record-buffer
size. Checked multiplication must fit that byte allowance and the platform
allocation range before table construction succeeds. Growth is fallible and
geometric, bounded by that record count. The byte allowance covers requested
record-buffer storage; allocator bookkeeping and the small table object are
additional. Admission validates before reserving and appending. Any returned
error leaves the existing table length and records unchanged.

A read view borrows one table with a caller-selected frontier no greater than
its current length. Reads at or beyond that frontier reject, including records
already present later in the table. A returned validated record has private
fields and immutable accessors. Binding a root checks the expected particle
against the record resolved within the view. The caller is responsible for
obtaining that expected particle and frontier from its verified statement or
preceding transition. A view itself establishes no job or transition boundary.

## Composition boundary

This table supplies authenticated noun/header/Cost reads to a future semantic
execution certificate: each accepted record is checked from previously accepted
records. Dense indices allow a later external-memory implementation without a
content-keyed verifier index. Current storage is bounded in memory.

The component has no execution-proof wire format or production Joy dispatch.
It does not discharge the existing tagged CCS builder's unresolved reads; that
guard remains unchanged. A separate disclosed semantic profile must specify and
check all opcode equations, computed continuations, LIFO state, exact budgets,
public program/subject/result bindings, chunk order and terminal completion.
Those requirements and actual compiler measurements precede SH7 acceptance.
Succinctness, zero knowledge and physical nox allocation/GC claims require
separate evidence. Both complete frozen self-build proofs remain the SH8 gate.

## Acceptance

Tests use actual nox-created DAGs as a differential oracle for native identities
and all Cost cases. Independently forged definitions must reject changed header
or particle limbs, noncanonical atoms/particles, wrong Dynamic or either Cost
limb, missing/forward/self references, wrong ordered children and wrong expected
root. Tests cover duplicate occurrences, malformed bodies, unselected dynamic
arms, saturation, restricted frontiers, exact and one-below limits, and unchanged
state after rejection. Observed sizes and timings belong in `audit/` with exact
source and command identities.
