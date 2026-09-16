---
status: draft
implementation: under-review
---

# Experimental tagged symbolic relation

This proposal defines `execution::tagged`, an opt-in circuit kernel. It does not
change `specs/execution.md`, existing execution relations, proof envelopes, or Joy
verification. No production prover invokes it. It is not a general nox relation.

## Supported language and limits

The formula and subject topology are public. Subject atoms are field inputs.
The supported static formula subset is axis (opcode 0, literal axis),
quote (1), cons (3), branch (4), field add/subtract/multiply (5/6/7), inverse (8),
structural equality (9), ordering/word operations (10..14), quoted static
composition (2), and pattern-15 hash. Axis zero returns structural identity.
Branch selection is zero=true, nonzero=false. Both arms are compiled, including
arms with different noun shapes. Positive axes traverse the current symbolic
subject. Computed continuations (other than the quoted-static composition below),
calls and state are unsupported. Unsupported operations cause a compile error
even in an inactive arm; they are not modeled as native failure.
Malformed formula structure within the supported opcode subset and active
projection into an atom make execution unsatisfiable. The same errors in an inactive arm impose no execution obligation.
All program atoms must be canonical Goldilocks values, including quoted or
inactive data. Resource policy is at most 128 tree depth, 4096 source/subject
nodes, 4096 evaluator calls, 4096 constructed carrier nodes, 32768 gates/rows.
Exceeding policy is a compilation error, not a statement about native validity.

## Carrier and constraints

A verifier-derived sparse tree has a Boolean tag t (0 atom, 1 pair), payload v,
and optional child carriers. Enforce t(1-t)=0 and tv=0. A carrier without child
slots has t=0. For each child c enforce (1-t)c.t=(1-t)c.v=0. Descendants therefore
have unique all-zero padding when absent; pairs have zero payload. Shape is the
union of formula branches, independent of input values and claimed output.

The root activity is one. Test payload x has nonzero selector s constrained by
s=x*i, s(1-s)=0, x(1-s)=0 and (1-s)i=0. Test is required to be an atom only when
active. Branch activities are a(1-s), as. Every inactive result is canonical
atom-zero. Projection requires a(1-t)=0 before accessing a child; a missing child
requires a=0. Atom-consuming operations require at=0. Inverse y requires
 a(xy-1)=0 and (1-a)y=0. No prover-only validity checks replace these rows.
Costs are activity-gated own cost plus child costs (both mutually exclusive arm
costs for branch). Own cost is one except inverse/ordering 64, word operations32
and pattern-15 hash25. A checked worst-case bound
below the field modulus prevents integer cost wrap; budget checks use actual
public selected cost, not worst-case cost.

## Complete statement binding

R1CS/CCS alone is homogeneous: an all-zero vector satisfies its rows. A complete
statement **must additionally pin coordinate zero to one**, zero coordinate to
zero, all input coordinates, selected cost, and every output carrier tag and
payload under the same witness commitment. `verify_witness` does those checks
and evaluates every matrix row; it is a transparent local checker, not a proof.
`public_coordinates` provides that exact binding for a future reviewed backend.

The claimed output is traversed against the already derived schema. A pair at
an atom-only schema is rejected; missing descendants are bound to zero. Output
leaf flattening alone is forbidden: differently associated trees with identical
leaves are distinct outputs. Matrices and schema are never derived from claimed
output or witness values. The API exposes no serialization or proof format.

## Remaining general-execution work

Beyond quoted static composition, computed formulas need checked continuation
dispatch. Bounded dynamic memory
needs an authenticated shape/edge representation, and external calls/state need
complete relations. This kernel does not implement those algorithms or discharge
whole-VM release readiness. A production adapter would also need protocol domain
separation, authenticated relation identity, bounded wire decoding, reviewed
commitment integration, and proof-level adversarial tests.

## Structural identity consumers

Structural identity uses **the existing native Hemera**, not a replacement hash
or altered parameters. Each atom payload has a constrained canonical 64-bit
decomposition: Boolean bits reconstruct the field value, and high32=0xffffffff
requires low32=0, excluding the alternate representatives at or above p.
The native eight-byte LE encoding occupies state lane0=low56, lane1=high8+256,
with byte length8 in capacity lane10 and domain0. After the first permutation,
its first four lanes enter a zero state with FLAG_CHUNK=4 in lane9 and counter0;
a second permutation produces the atom identity. Parent identity puts all four
left/right digest limbs in lanes0..7 with FLAG_PARENT=2 in lane9. Native nox
uses is_root=false: FLAG_ROOT is deliberately not set even for the top noun.

Every permutation uses Hemera's 16-lane linear layers, pinned round constants,
eight full x^7 rounds and sixteen inverse partial rounds. Inverse at zero is
constrained to zero. No runtime native hash call supplies unconstrained witness
digest values; native code is used only for fixed linear-layer coefficients.

A fixed atom/pair tag chooses that digest construction. A symbolic tag computes
both alternatives and selects **all four** coordinates under the constrained tag.
Absent child carriers stay canonical atom-zero. Stable carrier IDs and operand
wire identities memoize repeated symbolic hashing; caches depend on neither
witness values nor claimed output. Existing gate/node limits still apply, so a
large otherwise valid noun may fail compilation with Limit.

Axis0 returns [[h0 h1] [h2 h3]], activity-masked as every other result. Pattern15
evaluates its argument and adds a plain permutation of its structural digest in
lanes0..3, all other lanes zero; its own native cost is25. Equality evaluates both
nouns and returns0 iff **all four structural digest limbs match**, otherwise1.
Each limb difference has a constrained nonzero bit; their Boolean OR produces
the inequality result. This follows native identity semantics even for atoms,
without substituting field-value equality or comparing only digest limb0.

Native Hemera's cryptographic security assumptions and external review gates
remain unchanged. Functional identity matching is not evidence of independent
cryptographic review, and a collision would affect native and circuit equality
the same way.

## Ordering, words and quoted static composition

Opcode10 compares the canonical unsigned64 representatives, returning0 for
strictly less and1 otherwise; own cost64. Both operands must be active atoms.
Canonical bit decomposition is the same `<p`-constrained representation used
by structural hashing. A most-significant-difference recurrence is constructed
from all64 Boolean bit pairs; no modulo-field comparison substitutes for it.

Opcodes11 (XOR),12 (AND),13 (NOT),14 (left shift) operate on unsigned32 atoms;
own cost32. A word operand is multiplied by current activity before Boolean
32-bit decomposition and exact recomposition. Thus an active out-of-range value
makes the circuit unsatisfiable, while an inactive operand forces canonical
zero bits. NOT complements exactly32 bits. Shift discards overflow bits, and
any canonical32-bit shift amount >=32 produces0 (it is not reduced modulo32).
All result carriers remain activity-masked. These range/type failures follow
native execution semantics, not compile-time shape rejection.

Opcode2 is supported when its RHS formula is **syntactically `[1 continuation]`**.
The left formula is evaluated on the original subject; `continuation` is then
compiled against that actual symbolic result, including its optional topology.
The RHS quote is a verifier-known constant with cost1; no prover-chosen formula
or output shape enters matrix generation. Total cost is1 for compose,1 for
that quote, plus selected left and continuation costs. Quoted malformed
continuations impose gated native failure; valid unsupported continuations
remain Unsupported. A RHS computed by any other formula remains explicitly
Unsupported, even if a particular witness or native execution yields a constant.
Positive axes inside the continuation require active pair tags at each step;
an invalid projection in an unselected branch imposes no execution obligation.
Compilation and witness allocation retain the same depth/call/node/gate bounds.
