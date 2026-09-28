---
status: draft
implementation: planned
---

# Dynamic noun memory for native execution

This proposal extends the native Zheng execution relation toward computed
continuations and compiler-sized noun data. The next component after bounded
witness capture is algebraic noun/Cost derivation, followed by authenticated
memory and transitions. Existing production proof contracts remain unchanged.
This draft supplies no compiler execution proof or SH7/SH8 acceptance.

## Baseline and ownership

The API baseline is Zheng `b54b209b91b8bf99c2975c4c24493a2411c23079`.
The capture/semantics baseline is nox
`71b5860219f0e0810200946e4445e5fdf54269dd`, proposed in
[PR25](https://github.com/cyberia-to/nox/pull/25). These design inputs are
separate from the frozen SH6 bootstrap pins.

Nox owns execution and bounded capture. Zheng independently constrains the
candidate witness and verifies proofs. Joy owns artifact/job admission,
production dispatch and complete statement binding.

## First implementation slice

Add an internal reusable noun-and-Cost gadget to the existing CCS execution
implementation. Its schema depends only on a public version and explicit
resource bounds. Witness topology, tags, values and claimed results must never
select the matrix layout. This component exposes no standalone execution
certificate or Joy proof path.

The proposed owner is the existing `execution::tagged` builder, with separate
`node_cost.rs` and `uint64.rs` components and minimal reuse changes in its hash
and build helpers. Header validity and Cost derivation remain composable, so
authenticated reads can reuse previously validated records.

A record contains its four-limb structural particle, atom/pair tag, canonical
atom payload, ordered child particles and independently derived Cost metadata.
Cost contains an Exact/Dynamic selector and unsigned 64-bit bound. The native
structural particle commits to noun content; Cost requires its own constraints.

Local derivation uses a fixed set of read ports. Constrained selectors determine
which ports are active and the exact particles requested, including the nested
reads needed for branch metadata. The next memory component authenticates the
returned records and their derived metadata. Local consistency of an otherwise
unconstrained record cannot discharge a memory read obligation.

The proposed local profile has one candidate definition and six ports: L/R
read its children, A/B read R's children where needed, and Y/N read B's children
for branch metadata. Branch needs B's shape before activating its arm reads;
call metadata uses A's Cost and excludes the check formula's Cost. Every
activation and requested particle is constrained within the same fixed schema.
This port count is a design proposal, without a measured gate-size claim.

Child Cost values are explicit read premises until the memory component
authenticates their derivation. An execution relation cannot be finalized with
unresolved read obligations. Component tests bind these premises publicly.

Keep this interface independent of the memory representation. Component tests
may bind supplied records as explicit public inputs. Whole-compiler execution
needs authenticated reads bounded per transition. A dense selection over every
prior noun at every step is outside the intended scalable architecture.

## Node identity constraints

- Activity and atom/pair selectors are Boolean. Inactive ports have a specified
  zero encoding. Pair payloads and atom child fields have canonical zero padding.
- Atom payload has a canonical Goldilocks bit/limb representation, strictly below
  the modulus. Field recomposition alone cannot exclude alternate representatives.
- Reuse the native Hemera algebraic gadget and exact framing from the
  [tagged relation](tagged-symbolic-relation.md#structural-identity-consumers).
  Preserve atom byte encoding, ordered children and all four digest limbs.
- A constrained tag selects atom or pair construction. Native hashing can supply
  test oracles and candidate values; accepted digest coordinates follow from rows.
- Parent child particles, requested read particles and returned record particles
  match in every limb. Gadget caches depend on schema/wire identities.
- Any two active records with the same particle have identical header and Cost.
  Include the candidate and six ports: at most 21 constant-size comparisons.
  This local coherence requirement complements the later global memory argument.

## Complete Cost derivation

Match `nox/rs/data/reduction.rs::compute_pair_bound` and `nox/rs/data/cost.rs`,
including quoted data and unselected code. A small execution opcode subset
still requires every metadata case.

Atoms have Exact(0). A pair with a pair-valued left child, or a left atom outside
0..17, has Exact(0). Otherwise the left atom selects the native fixed base cost:

| Pattern | Numeric bound | Dynamic selector |
|---|---|---|
| 0, 1 | base | false |
| 2, pair body x/y | saturated base + bound(x) + bound(y) | true |
| 3,5,6,7,9,10,11,12,14,17, pair body a/b | saturated base + bound(a) + bound(b) | dynamic(a) OR dynamic(b) |
| 4, body test/[yes no] | saturated base + bound(test) + max(bound(yes), bound(no)) | OR of all three child selectors |
| 8,13,15 | saturated base + bound(body) | dynamic(body) |
| 16, pair body tag/check | saturated base + bound(tag) | true |

A missing required body pair or nested pair falls back to Exact(base).
That metadata rule does not establish successful execution of malformed code;
formula validity is a separate transition constraint.

Represent u64 with range-constrained limbs/bits: `u64::MAX` exceeds the field
modulus. Prove carries and overflow before selecting saturation; constrain
unsigned max and Exact/Dynamic independently. Only bound operations saturate.
Future reservations/refunds use checked integer arithmetic and reject overflow
or underflow, so they need separate gadgets.

The proposed u64 representation uses two 32-bit limbs. Addition constrains raw
low/high result limbs and Boolean carry/overflow; overflow selects two maximum
32-bit output limbs. Unsigned max selects both limbs with one proven selector.
The current scalar `TaggedRelation.cost` remains field-bounded and cannot serve
as an arbitrary u64 metadata slot. Cached Cost is a reservation bound; actual
charged reductions require separate transition constraints.

## Following memory component

Authenticate definitions and reads, preserve child order, reject conflicting
definitions for one particle, and bind public initial roots and every chunk
boundary. Definitions use previously authenticated children. A before-state
cannot read nodes created after that step. GC recreation preserves logical
identity and derived metadata; physical arena positions are host details.
All reads belong to the same authenticated root/epoch and allowed birth frontier.
The initial root must be derived from the admitted input or linked to a previously
verified state. An arbitrary root supplied by a prover is insufficient.

An authenticated append-only log, dictionary or permutation-based argument may
implement the read-port interface. The choice remains open until concrete
constraints, adversarial tests and bounded measurements are reviewed. Commit to
Cost metadata with noun content, or prove its derivation at each accepted use.
Chunk state binds memory commitment, position, complete logical continuation
state, remaining budget and the same job/profile. Only a later terminal-state
relation can establish completed execution from a valid sequence of chunks.

## Component acceptance

Independently mutate candidate witnesses and check every row against the expected
public coordinates. Pin the constant coordinate to one and reject conflicting
or duplicate public coordinates. Equal public profiles must produce identical
circuits across different witness topology, values and Cost selectors.

Vectors cover canonical atom boundaries, ordered pairs with identical leaves,
every particle limb, malformed bodies, every Cost opcode case, Exact/Dynamic
swaps, inactive padding, forged read requests/records, carry/overflow and u64
saturation. A compact shared DAG exercises large bounds without a huge tree.
Invalid witnesses are constructed independently of the honest generator.
Include a disabled mandatory port, same-particle/different-Cost records, Dynamic
in an unselected branch, the 32-bit carry boundary and Cost values around the
field modulus. Test changed expected coordinates and corrupted witnesses through
the existing proof backend, with schema version, fixed input slots, candidate
particle/Cost and read premises bound explicitly.

Declare public caps and exact/one-below tests before measurements. Record matrix
dimensions/nonzero entries, witness bytes, build and complete verification times
under `audit/`, with exact commands and revisions. This draft establishes no
whole-compiler scaling, proof-size or latency result.
Existing gate limits keep rejecting oversized circuits. The proposed component
does not presume that its composed gadgets fit the current 32768-gate limit.

## Subsequent acceptance

After noun/Cost derivation and authenticated memory, constrain Enter/Return,
LIFO frames, branches, computed formulas, reservations/refunds and one final
empty-stack completed state. Then adapt the existing Zheng proof backend with
verifier-derived matrices and full public binding. Its current public backend
discloses and checks the full witness; dynamic execution inherits no succinctness
or zero-knowledge claim automatically.

Joy integration binds exact program, structured subject, output topology,
compiler JOB1 and extracted ART1. The full [SH7 gate](../../../trident/reference/self-hosting.md#sh7-native-proof-relation)
requires production dispatch, the actual SH3/SH4 workload, complete bindings,
declared limits, measurements and independent adversarial verification; a small
pilot alone is insufficient. Proofs of both complete frozen self-builds are SH8.
SH6 remains reproducible native self-compilation.
