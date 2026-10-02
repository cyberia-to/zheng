# Disclosed successful evaluation DAG

Status: experimental component for a disclosed dynamic execution certificate.

## Statement and storage

An evaluation store owns one immutable [validated noun-memory view](disclosed-noun-memory.md).
Every noun index resolves through that same view for the store's lifetime. An
untrusted candidate supplies object, formula and result indices and exactly
zero, one, two or three prior evaluation indices. Prior indices are strictly
less than the evaluation count before admission. The verifier derives all
metrics and admits the candidate only after checking the complete rule below.
Every premise's object and formula are bound by all four particle limbs, rather
than occurrence indices. Each result is bound in the same way. Equal identities
of different structures retain noun memory's Hemera collision assumption.
Immutable accessors expose the admitted candidate, derived metrics and its three
full particles. Indices remain local to the fixed noun view.

The caller bounds evaluation count, requested record-buffer bytes, exact cost,
active frames and expanded logical steps. Buffer-size multiplication is checked
against the byte allowance and platform allocation range. Growth is geometric,
fallible and bounded by the declared count. An error leaves existing records
and their count unchanged. Allocator bookkeeping is additional to record-buffer
storage. Validated records have private fields and immutable accessors.

## Successful rules

Decode the formula as `[tag body]` with an atom tag in 0..15. The dispatch costs
are, in tag order: 1, 1, 1, 1, 1, 1, 1, 1, 64, 1, 64, 32, 32, 32, 32, 25.
Each rule checks the required body shape and exact premise arity.

| Tag | Premises, in order | Result predicate |
| --- | --- | --- |
| 0 axis | none | Body is a canonical atom address. Address 0 returns `[[h0 h1] [h2 h3]]` containing the object's particle limbs. Address 1 returns the object. Larger addresses follow their bits after the leading one, left for zero and right for one; every traversed noun is a pair. |
| 1 quote | none | Result equals the body. Quoted data is unrestricted. |
| 2 compose | `(object,a)`, `(object,b)`, `(result0,result1)` for body `[a b]` | Result equals the third premise's result. The continuation formula is computed. |
| 3 cons | `(object,a)`, `(object,b)` for body `[a b]` | Result is a pair of the two premise results, in order. |
| 4 branch | `(object,test)`, `(object,chosen)` for body `[test [yes no]]` | Test result is an atom; zero selects yes and every nonzero value selects no. Result equals the chosen premise's result. |
| 5, 6, 7 | two operand evaluations as for cons | Both results are atoms; result is their Goldilocks sum, difference or product. |
| 8 inverse | `(object,body)` | Child result is a nonzero atom and result is its field inverse. |
| 9 equality | two operand evaluations | Result is atom 0 when all four result particles match, otherwise atom 1. |
| 10 less-than | two operand evaluations | Atom operands use canonical u64 order; result is 0 for less-than, otherwise 1. |
| 11, 12, 14 | two operand evaluations | Atom operands are below 2^32. Result is xor, and or left shift masked to 32 bits. Shift counts at least 32 produce zero. |
| 13 complement | `(object,body)` | Child is an atom below 2^32; result is its 32-bit complement. |
| 15 hash | `(object,body)` | Initialize native Hemera StepSponge with the child's four particle limbs followed by four zeros, with zero capacity. Apply its initial MDS and 24 rounds. Result is hash-data containing the first four final canonical limbs. |

Only evaluated invocations require supported tags. Quoted and unselected nouns
may contain malformed formulas or service tags. Inverse zero, malformed shapes,
invalid operand types and failed axis paths have no successful rule. The
verifier checks primitive field/hash equations directly and never calls the
nox evaluator, compiler or a prover-supplied relation.

## Derived metrics and budget theorem

For each evaluation, derive exact cost as dispatch cost plus the sum of all
premise costs, expanded occurrences as one plus the sum of premise occurrences,
and peak active frames as one plus the maximum premise peak, with a zero maximum
for leaves. Repeated premise indices count repeatedly. Logical steps equal twice
expanded occurrences. Every addition and multiplication is checked; overflow
rejects. These quantities use integer arithmetic, without saturation or field
reduction. Noun Cost metadata keeps its distinct saturating semantics.
Admission also checks that an Exact noun bound covers the derived exact cost.

For a finite successful derivation of exact cost c, native pure sequential
execution with any u64 budget B >= c returns the same result particle and B-c,
subject to adequate host resources and no cancellation. Correct Exact(b) noun
metadata bounds a successful child's cost by b. A unary reservation therefore
gives the child an adequate bound or the entire available budget and refunds
the unused portion. Binary partitioning gives both children adequate bounds or
threads the remainder sequentially; both charge exactly the two child costs.
Compose then charges its computed continuation; branch charges the test and
selected arm. All finalizers preserve the residual budget passed to them.

Saturated metadata cannot cause a partition overflow: positive dispatch cost
leaves at most u64::MAX-1, so a saturated bound or bound sum of u64::MAX selects
the sequential fallback. Exact cost itself must fit u64. The native continuation
stack's peak equals the derived peak, and an entirely captured successful run
has two logical transitions per expanded invocation, including terminal root
return. Multirow primitive traces and noun-allocation events are separate.

## Final binding and scope

Final binding always selects the last admitted evaluation and checks caller
expected object, formula and result particles, exact cost, budget and frame
bound. The budget must cover the derived cost and the frame bound must cover
the derived peak and stay within the store's configured frame maximum. The
returned immutable summary includes the remaining budget.
The caller obtains these expectations from its authenticated public statement.

This component establishes successful semantic derivations over one validated
memory view. A transport, job/source/options binding, production Joy route and
actual compiler proof measurements remain separate integration work before SH7
acceptance. It makes no physical allocation, resident-memory, GC-work, deadline,
LIM1, succinctness or zero-knowledge claim. Both complete frozen self-build
proofs remain the SH8 gate.

## Acceptance

Differential tests compare native successful evaluations for every supported
opcode, computed continuations and repeated premises at exact/excess budgets
and exact frame limits. Adversarial tests change noun keys, result topology,
premise arity/order/references, claim fields and resource limits; invalid types,
inverse zero and overflow reject. Saturated unselected metadata and unselected
service/malformed formulas exercise budget-independent success. Observed results
belong in `audit/`, with exact source and command identities.
