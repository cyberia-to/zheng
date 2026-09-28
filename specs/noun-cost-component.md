# Internal noun and Cost component

This experimental component implements local noun identity and cached Cost
derivation inside `execution::tagged`. It is the first component of
[dynamic noun memory](props/dynamic-noun-memory.md). It exposes internal builder
primitives and unresolved read obligations. Production execution and Joy proof
dispatch remain unchanged.

## Schema and declared bounds

Version 1 has one candidate definition and six read ports, in order L, R, A, B,
Y, N. Every record has 18 field coordinates: activity, pair selector, atom value,
four particle limbs, four left-child limbs, four right-child limbs, Dynamic
selector, low and high 32-bit Cost limbs. A component test schema contains one
version coordinate followed by these seven records: 127 input coordinates.
Inputs, opcode values and noun shapes never select circuit layout.

The builder keeps its existing ceiling of 32768 operation wires and 32768
constraint rows. One local component per builder is supported; a second attempt
rejects before extending the builder. A smaller caller-selected test ceiling
can only tighten the existing gate ceiling. The maximum padded witness extent
is 65536 field coordinates. These are declared limits, not measurements or
whole-compiler capacity claims.

## Identity and read premises

Activity, atom/pair and Dynamic selectors are Boolean. Every inactive record is
all zero; pair values and atom child fields are zero. Atom values are canonical
Goldilocks values, including the strict modulus check in Hemera bit encoding.
All seven headers use the native atom/pair Hemera framing and constrain all four
particle limbs. Atom Cost is Exact(0). Pair read Costs remain explicit premises.

L/R are active for an active candidate pair. For an atom-valued L in opcode
range, R's pair selector controls binary and call operands. A/B read R's
children for binary opcodes. Call activates A only. Branch first activates B
to inspect rest; a pair-valued B activates A, Y and N. Unary metadata uses R
directly. All requested particles and activation masks follow from constraints.
Inactive requests are zero. Active requested/returned particles match in every
limb. Across candidate and ports, equal particles require equal header and Cost;
all 21 possible record pairs are checked with fixed layout.

`PendingNodeCost` carries all six read obligations. The builder records their
unresolved status and refuses ordinary execution-relation finalization. This
component provides no memory resolver. Tests alone may finish a raw component
instance with all fixed record coordinates declared as public premises. Its
conditional local property does not authenticate a global noun/Cost table.

## Cost constraints

The complete 0..17 table and malformed-body fallback match
`nox/rs/data/reduction.rs::compute_pair_bound` and `nox/rs/data/cost.rs` at
`71b5860219f0e0810200946e4445e5fdf54269dd`. Quoted data and unselected branches
retain the same metadata interpretation. Atoms, non-atom pattern heads and
out-of-range opcode heads have Exact(0). A missing required pair has Exact(base).
Compose and call with valid bodies are Dynamic. Branch propagates Dynamic from
test and both arms independently of which numeric bound wins unsigned max.

The u64 helper constrains both operands to 32-bit limbs, Boolean carries and
overflow, exact nonwrapping limb equations, and saturated output selection.
Unsigned max uses one proven comparison selector for both limbs. Values from
the field modulus through u64::MAX are valid Cost bounds. Atom values retain
their different field-canonical domain. Cost metadata and charged execution
reductions are separate quantities; reservation/refund transitions are future
components.

## Verification and scope

Component tests derive matrices from this fixed schema, pin the version and
all input records, and use the existing direct CCS proof backend. The backend
pins coordinate zero to one. Public coordinates are strictly ordered, unique,
in range, and exclude that mandatory constant coordinate. Tests independently
modify input/internal witness cells and expected public coordinates, including
same-particle conflicts, disabled reads and canonical encoding attacks.

Authenticated memory must later discharge these obligations against one valid
root/epoch and prior birth frontier, derive initial state, and authenticate all
Cost definitions. The read-port interface does not select over a growing global
table. GC arena positions do not enter this component. The current public proof
backend exposes the full witness; this component makes no succinctness, ZK,
dynamic execution, compiler-proof or SH7/SH8 acceptance claim.

Measured circuit sizes, proof costs and test commands belong in `audit/`.
