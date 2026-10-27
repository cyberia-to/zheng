# Bounded disclosed semantic stream

Status: experimental verifier component for successful pure execution.

This component stages the rules in [disclosed evaluation DAG](disclosed-evaluation-dag.md)
over a bounded continuation stack and bounded cache of opaque checked summaries.
It independently checks primitive equations and never invokes the nox evaluator.
The finite DAG and staged verifier must stay synchronized for tags, dispatch
costs, primitive equations and derived integer metrics.

## Session and authenticated facts

Construction pins the root's complete object and formula particles. `enter`
receives an immutable validated noun-memory view and object/formula indices.
Their particles must match the pending invocation key. It decodes the formula
and copies its complete rule facts: opcode, object/formula particles, cached
Cost, and required operand-formula particles. Axis navigation is checked now,
while the object remains available. Quoted and unselected formulas may contain
unsupported or malformed code. Every evaluated invocation has a pure tag 0..15.

An activation retains no noun indices or borrowed noun records. Completed
children supply an opaque checked result with its particle and either canonical
atom value or ordered child particles, plus checked metrics. Primitive type
checks, branch selection and computed continuation keys use these copied facts.
They remain valid after the transport discards an entire noun table and supplies
a new independently validated table with unrelated occurrence indices.

Each `finish` receives a current validated result index. Its complete header is
read from that view and checked against the top activation's output rule. Hash
data requires the expected pair-of-pairs topology and all four canonical limbs.
The result's authenticated header facts are retained in the checked summary.
There is no constructor or import path for trusted activations or summaries.

## Staged rules and LIFO order

The pending key returned by `expected()` is the only invocation that may enter
or reuse a cached summary. It is absent while a frame awaits `finish` and after
root completion. An entered leaf becomes ready to finish immediately. Other
invocations request these children in order:

- Unary: the body's evaluation under the parent's object.
- Binary: left then right operand formulas under the parent's object.
- Compose: the two operand evaluations, then `(left result, right result)` as
  computed object and formula. Its result equals the continuation result.
- Branch: the test; then yes for atom zero or no for every nonzero atom. Its
  result equals the selected child result.

Accepting a child advances exactly one top activation. Every completed child
adds its entire exact cost and expanded occurrences, even on cache reuse. Peak
frames are one plus the maximum child peak. Leaves start with dispatch cost,
one occurrence and one frame. Steps equal twice occurrences. All arithmetic is
checked, and configured cost/frame/step limits apply during composition. Exact
noun metadata must cover the completed evaluation's derived cost. The successful
budget-independent theorem in the finite DAG specification applies unchanged.

`peak_frames` counts logical invocations, including a leaf awaiting finish. It
is the derivation height and a conservative host frame allowance; raw live
continuation-stack depth may differ. The surrounding runtime must state which
telemetry it compares rather than equating those two quantities.

The primitive equations are those of the finite component: ordered cons;
Goldilocks arithmetic; inverse of a nonzero atom; four-limb particle equality;
canonical atom ordering; 32-bit word operations; native hash-data construction;
and axis-zero introspection distinct from opcode 15's permutation.

## Summary cache

The cache contains a fixed number of slots. A successful `finish` may put its
new checked summary into a named slot, replacing the previous occupant. That
slot's u64 generation increments with checked arithmetic, starting at one.
The returned handle contains slot and generation. `reuse` requires an occupied
slot with exactly that generation and a key equal in every particle limb to
the pending invocation. It contributes the complete stored metrics and result
facts as a child without reading any noun indices. A stale handle or a handle
without a matching checked local occupant rejects. Replacement is explicit
eviction; there is no serialized-summary import.

Readonly cache inspection returns opaque summary copies for a producer's key
dictionary. Such copies cannot be submitted back to the verifier. Active parent
frames own the facts they need, so cache replacement cannot change an accepted
child. Generations, cache state and activations belong to one session.

## Bounds, failures and completion

The caller bounds active/derived frames, cache slots, requested total stack and
cache buffer bytes, exact cost, expanded steps and semantic event count. Checked
size arithmetic must fit the allowance and platform allocation range. Both
buffers reserve fallibly at construction; event processing allocates no buffers.
Allocator bookkeeping and the stream object are additional. Noun-table storage,
wire bytes and reset/snapshot work are bounded by the surrounding transport.

An event is enter, finish or reuse. Every attempted event checks the count cap;
an event error poisons the instance, and later events or terminal binding reject.
Readonly getters import no evidence and do not consume events. Root completion
requires exactly one completed root and an empty activation stack. Further
semantic events reject. `bind_terminal` consumes the session and compares root
object/formula/result particles and exact cost to caller expectations. Budget
must cover cost; the supplied frame bound must cover the derived peak and stay
within the configured frame limit. It returns a checked summary and remaining
budget. Truncation, completion before all children, extra children and extra
root invocations cannot produce a terminal summary.

## Integration and acceptance

The transport owns complete noun resets, framing, versions, machine/job context,
chunk order, compression limits and rejection of trailing bytes. A reset may
occur between any semantic events because the verifier retains particles and
checked primitive facts, rather than indices. Resetting memory does not reset
the invocation stack, cached summaries, generations or derived metrics.

Tests compare native evaluation and the finite DAG oracle, exercise resets at
every continuation phase, preserve cached results across index remapping, and
reject changed keys/results, wrong order, stale generations, invalid types,
over-budget metrics, allocation failures and incomplete/extra roots. This
component establishes no physical allocation/GC/deadline/LIM1 claim, private or
succinct proof, production Joy integration, or whole-compiler SH7/SH8 acceptance.
