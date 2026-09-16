# General bounded Nox relation: independent architectural review

Status: design proposal, no production/specification change or new proof run.
Read the repository CLAUDE, current execution/backend specs and the implementation
paths listed below. The existing supported relation remains the security boundary
until its replacement passes the gates in this report.

## Current boundary and concrete gaps

`execution/relation.rs` represents atoms by Constant/Wire and pairs by a Rust
`Value::Pair`. Shape is compile-time information. `mux` refuses atom/pair joins;
`linear`, axis traversal, structural hashing, look root extraction and output
coordinate allocation all rely on that same static shape. Removing only the mux
error would leave these other consumers incorrect or unconstrained.

For a subject `[x 0]`, the native formula
`[4 [[0 2] [[1 7] [1 [8 9]]]]]` returns atom7 when x=0 and pair[8 9] otherwise.
The current relation rejects the differing branch shapes. A second class is an
inactive structurally invalid branch: native evaluation can return7 while the
unselected arm would project an axis through an atom. Current symbolic projection
can reject that formula at construction time, before activity can gate the error.
The same issue applies to arithmetic or state-root projections of optional pairs.
These examples are semantic/source analysis, not newly executed test receipts.

Composition is a separate mechanism. `relation_eval.rs` evaluates its two
children, then `static_noun` requires the produced continuation to contain only
constant atoms/pairs. A continuation whose opcode, axis or literal comes from an
input/witness cannot be handled merely by changing the noun result carrier.

Native reference semantics are in `nox/rs/patterns`: branch requires an atom test,
zero selects yes, nonzero selects no, and only the chosen arm executes. Compose
evaluates two children, then applies the computed formula to the computed object.
The native CallProvider can supply a general noun; today's Zheng/Joy secret
transport supplies atom witnesses only. A full native noun-call interface also
needs an explicit bounded witness codec, not just a new branch implementation.

## Recommended first implementation: sparse tagged union shapes

Keep the existing verifier-derived symbolic circuit for public static formulas.
Replace hard-coded Rust shape discrimination with a symbolic noun carrier:

- A verifier-derived sparse schema lists possible node positions. It is the
  union of both possible branch shapes, recursively; no full2^depth tree is
  allocated. Static Atom/Pair positions remain optimized special cases.
- Each optional node has a constrained atom/pair tag, an atom payload and
  child carriers. Pair payloads are zero. Absent child subtrees use one fixed
  zero encoding. Presence propagates from the parent tag.
- Tag booleanity and ordinary data-copy/arithmetic constraints hold everywhere.
  Semantic preconditions such as "this active operation needs an atom" are
  gated by execution activity. Canonical padding prevents unused carrier fields
  becoming unbound alternative outputs or nondeterministic witness recipes.
- `mux` selects tags, payloads and descendants according to the same constrained
  selector used for cost/activity. Schema union is derived from the formula and
  public subject shape, never from the selected witness branch or claimed output.

Implement `require_atom(value, active)` and `project_child(value, side, active)`
first. They return total symbolic expressions with canonical dummy values for
inactive cases and constraints rejecting active type/axis errors. Update every
consumer to use them: arithmetic, comparisons/bit words, branch tests, calls,
axis traversal, look namespace/key/root extraction and hashing. Do not leave
old host-side shape matches that reject an inactive semantic error.

Quote creates constant tagged data; cons combines complete tagged children.
Axis1 returns the entire carrier; ordinary static axes project with per-level
active pair checks; axis0 returns the complete structural digest as the native
balanced four-field noun. A statically malformed subformula or unknown opcode must compile to a
constrained failure (`activity=0`) with canonical dummy results: native execution
may legitimately skip that arm. This applies only to genuine native errors;
an unimplemented valid feature must never be relabeled as a native error to
hide missing coverage. The formula skeleton is still publicly known here.
Fully dynamic decoding belongs to the next stage.

The sparse schema's worst case is the union of all branch shapes, potentially
much larger than one selected noun. Charge that real schema and emitted rows to
explicit construction limits before allocation. Current4096 symbolic-node,
128-depth,4096-call and32768-row limits must be measured on the new construction;
no claim that every existing bounded source necessarily fits is justified yet.
This stage closes static-formula variable noun/result shapes within declared
resource bounds. It does not close computed-formula execution by itself.

## Hashing, equality and output topology

Reuse the exact existing Hemera gadgets. Atom identity hashes canonical LE-u64
bytes with the native leaf framing; pairs use full four-limb child identities
and parent framing. Hashing an optional node computes/selects the atom or pair
identity according to its constrained tag. Cache symbolic digests by carrier
identity to avoid duplicating full permutations on every use. Native pattern15
adds its final plain StepSponge permutation after structural identity; axis0
does not. Equal compares all four digest limbs, using Nox zero=true semantics.
Do not substitute a new tagged hash or one-limb digest for native identity.
Hemera cryptographic-assurance claims remain separate from circuit correctness.

Public output can no longer be authenticated only as a vector of atom leaves.
`[[1 2] 3]` and `[1 [2 3]]` have identical leaf vectors but different nouns.
Currently the verifier independently fixes output_shape; that protection disappears
if shape becomes witness-dependent. Add a bounded canonical output noun encoding
(prefix Pair/Atom tokens, exact length, canonical atoms, one complete tree) and
bind it to the same output carrier as payload/cost. The verifier can assign every
sparse schema node a required tag/value/presence from the expected public noun,
rejecting shapes outside the verifier-derived schema. This binding does not let
the claimed output alter circuit topology. Unused positions must be canonical.

For a future indexed-arena carrier, constrain a canonical bounded traversal of
the result root to that public encoding, or constrain the full expected native
structural digest with explicit shape/length disclosure requirements. The former
provides exact topology binding without adding a new reliance on digest collision
resistance beyond the existing native identity semantics.

Version ExecutionStatement/transcript and the Joy public/private/state envelopes.
Keep leaf-vector CLI output as an explicitly derived convenience if desired;
verification that promises an exact noun needs its canonical topology too. An
old leaf-only artifact must not be relabeled as the new relation. Witness shape
must not select a different relation or a different verifier.

## Complete computed-formula support: bounded machine relation

Use a verifier-derived bounded evaluator with explicit control frames and a
bounded immutable noun arena. This is a further concrete implementation stage,
not a fallback to the old trace certificate or native rerun.

Public policy chooses maximum evaluation steps T, arena capacity N, continuation
depth D and call-witness capacity K. These limits and relation version are bound
in the statement/transcript. The verifier builds one fixed relation from these
limits, the canonical program and public subject shape. Opcode, formula contents,
selected branch, allocation count and continuation stack are witness wires.
They must never determine matrix dimensions or coefficients.

Arena entries contain initialized/type bits, canonical atom payload, child IDs
and full constrained native digest. Cells reference initialized earlier entries;
range/ordering constraints forbid cycles, forward aliases and out-of-range IDs.
All inactive/unallocated entries use canonical padding. Program and subject roots
are linked to exact authenticated program/input nodes; wire0 remains public1.
Duplicate equal nodes may be represented without native hash-cons reuse, provided
semantic equality is by native identity and the public allocation bound explicitly
accounts for the chosen representation. Do not confuse that bound with native
arena reuse or reduction cost.

For a correctness-first implementation, use constrained one-hot reads: selector
bits, sum=activity, weighted index equality and selected-data equality. Every
read is tied to the same arena; no prover-supplied "looked-up node" is accepted
without these constraints. This costs O(T*N) for bounded reads plus node hash
work and is deliberately measurable. Optimizing to a sorted memory/permutation
argument is a separate cryptographic engineering change requiring its own tests;
the existing legacy universal step CCS does not supply a complete substitute.

Machine state holds running/halted flags, object ID, formula ID, result ID,
continuation frames, witness cursor and checked integer cost. A dispatch step
reads a pair formula, selects exactly one opcode0..17 and enforces its grammar.
Continuation transitions are constrained, including parent/child linkage:

1. Quote returns its body; axis projects/hashes the actual object.
2. Eager binary operations evaluate left then right and combine their results.
3. Compose evaluates both children and starts evaluation at exactly the resulting
   object/formula IDs. The computed formula is decoded by the same constrained
   dispatcher, including computed opcodes, axes and nested continuations.
4. Branch evaluates its atom test and schedules exactly the chosen arm.
5. Call evaluates an atom tag, obtains the next bounded witness noun, evaluates
   its check on `[witness, object]`, requires atom0 and returns that same witness.
6. Look evaluates namespace/key and reads authenticated state under the actual
   root extracted from its current object.

A halted state is absorbing with canonical padding. Initially execution is active
at the pinned program/subject roots. Final success requires a genuine empty
continuation stack and completed result before T; never allow a witness-selected
halt, skipped child evaluation or a timeout to masquerade as success. Dynamic
malformed formulas and active type errors have no successful witness. Inactive
branches cannot consume calls, perform lookups or fail type checks.

The opcode gadgets already implemented by the symbolic relation can be reused,
but their operand reads, dispatch selectors and transitions must be constrained.
Do not accept a host-produced instruction trace merely because each independent
row satisfies a local arithmetic gadget. The missing global linkage is precisely
the historic legacy-trace issue described in specs/decider.md.

## Cost, state, secrecy and backend invariants

Native reduction costs are dispatch costs, not CCS row counts or hash gadget
work: axis/quote/compose/cons/branch/basic arithmetic/eq/call/look1, inv/lt64,
word operations32, hash25. Charge selected native operations exactly; evaluator
bookkeeping must not inflate the claimed native cost. Range-constrain cost and
budget, require selected cost<=budget, and use checked host bounds ensuring no
field wrap (for the machine, T*maximum dispatch cost below p). Native's sequential
budget fallback means an expensive inactive arm must not consume the budget.

Public state continues binding each active lookup's exact namespace, key, value
and all four root limbs to authenticated BBG evidence. Inactive records have zero
payload and no evidence. Private state selection stays inside the CCS against
the complete authenticated public tables; table root/metadata/content are checked
before deriving the relation. Existing ten namespaces/2048-field table caps and
backend row/work caps remain explicit. A changing noun shape cannot change which
root is authenticated or redirect a look through an unchecked pointer.

Preserve secret call evaluation order and only active consumption. General noun
witnesses need a bounded tagged codec and canonical unused padding. Their values,
tags and intermediate shapes stay private in the Triton-backed protocol; public
output shape, public limits and public cycles can still reveal information.
The PublicTensor certificate remains fully public/linear and must reject secret
inputs. Do not advertise it as a private fallback when the private backend limits
are exceeded.

Both backends retain verifier-generated matrices/coordinates, constant wire1,
zero error, complete row verification and statement bindings. The Triton checker
must be regenerated from the exact new relation; the program digest cannot come
from the proof. PublicTensor must authenticate the complete same witness table.
Update limits coherently: current symbolic32768 rows, Trisha checker65536 rows
and columns/1M work, and public direct dimensions1M are different contracts.
Larger representations need measured capacity decisions, not unchecked overrides.

## Files and acceptance sequence

First update canonical execution/backend specs and format definitions. Suggested
small implementation modules under `rs/src/execution`: tagged value/schema and
projections, tagged output binding/codec, existing eval/hash/look integration;
then bounded arena/reads, evaluator frames/dispatch and cost for computed formulas.
Keep each module below the repository500-line guideline. Adapt statement/private/
state preparation and Joy's native-output comparison/CLI/wire paths together.
Trisha's generic CCS checker should require only format/limit integration, since
it already asserts every regenerated row and public coordinate.

Required adversarial cases before claiming completion:

- Atom/pair and differently nested pairs with identical leaf vectors; mutate only
  tags/topology, inactive padding, result root or claimed output length.
- Both branch choices, nonboolean field tests, nested branches, selected and
  inactive axis/type/inverse/range errors, state accesses and secret calls.
- Structural hash/axis0/pattern15/equality for asymmetric atoms/pairs, changed
  child digest and fourth-limb-only mutations; compare exact native semantics.
- Budget exact/one-less, unselected expensive branch, cost wire wrap attempt,
  premature halt, repeated/skipped frame, mutated intermediate result.
- Dynamic quote-built formula, input-selected formula, computed opcode/axis,
  malformed selected formula, bounded nested compose and exhausted step/depth.
- Arena uninitialized/forward/cyclic/out-of-range references, changed allocation
  tag, inconsistent duplicated reads, all-zero witness and free constant wire.
- Real call noun/check binding; skip/reorder/duplicate active witnesses; inactive
  calls consume none. Real state key/value/root mutations and private query tests.
- Malicious satisfying-witness attempts bypassing the honest prover, fresh public
  and private proofs, changed canonical program/input/output/cost/state claims,
  and fresh-process verification using only expected statement and artifact.

Different private witnesses choosing different shapes must produce the exact
same matrices/public-coordinate layout for the same public program, input shape
and limits. Record node/row/column/work counts, proof time, verifier time and
peak memory for both the sparse symbolic and bounded evaluator implementations.
Do not infer those measurements from native cycle counts.

## Independent verification questions

1. Is shape mismatch confined to branch mux? No: direct inspection found static
   assumptions in projections, scalar conversion, hashing, look and outputs.
2. Can old public output leaves authenticate a variable noun? No: distinct
   topologies can share all leaves; the current safety relies on fixed shape.
3. Does a dynamic result carrier alone support computed continuation formulas?
   No: `static_noun` is a separate code-generation boundary; dynamic dispatch and
   frame transitions must themselves be constrained.
4. Can existing proof backends secure the enlarged relation? They can assert a
   verifier-derived complete relation; they do not supply missing semantics or
   permit unchecked limits. Private/public disclosure contracts remain distinct.
5. Is proving native traces or legacy universal rows enough? No: program/root,
   operand/continuation linkage, selected effects and final output/cost must share
   one authenticated witness and be constrained globally.

Recommendation: implement the sparse tagged symbolic relation and exact output
binding now, with the bounded computed-formula evaluator as the next explicit
completion gate. Publish separate coverage for the two until both pass; neither
is a reason to drop the requested general-execution objective.
