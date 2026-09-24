# Experimental tagged relation validation

Date: 2026-09-12. Status: bounded kernel implemented and locally tested;
independent review and production integration remain open. This does **not**
close general nox execution readiness, amend the production execution contract,
or change any existing proof envelope/acceptance path.

## Contract and implementation ownership

The draft contract was written before implementation:
[`specs/props/tagged-symbolic-relation.md`](../specs/props/tagged-symbolic-relation.md).
The new implementation is isolated in `rs/src/execution/tagged/`:

- `mod.rs`: canonical input/output validation, exact public coordinates, complete
  transparent witness checker and compile entry point.
- `build.rs`: bounded gate allocation, Boolean tags, pair payload zero, absent
  child padding, verifier-derived sparse branch union, R1CS-to-CCS construction.
- `eval.rs`: activity-gated positive-axis projection, quote, cons, branch,
  field addition/subtraction/multiplication/inverse, native identity equality,
  axis-zero/pattern-15 digest consumers, quoted static composition and actual
  selected cost.
- `word.rs`: canonical U64 ordering, activity-masked U32 decomposition,
  XOR/AND/NOT/shift with native overflow and shift-range rules.
- `hash.rs`: existing Hemera permutation, canonical atom framing, optional-tag
  structural digest selection and stable symbolic memoization.
- `tests.rs`, `hash_tests.rs` and `word_tests.rs`: independent native reducer
  comparisons and direct malicious witness
  mutations. No proving library or new cryptographic construction is introduced.

The only edit outside new files is the authorized `pub mod tagged` export in
`execution/mod.rs`. Existing relation/private/state/proof modules are untouched.
There is no Joy dispatch, serialization, protocol format, automatic fallback,
state implementation or claim of complete dynamic nox support.

## Reproduced production limitations

These examples use the actual native `reduce` implementation, not a mocked
interpreter; the tests also assert that current production `compile_relation`
rejects each formula.

| Formula / subject | Native result | Existing relation | Tagged kernel |
| --- | --- | --- | --- |
| `[4 [[0 2] [[1 7] [1 [8 9]]]]]`, subject `[0 0]` | atom 7, cost 3 | shape rejection | satisfied, exact atom binding |
| Same formula, subject `[1 0]` | pair `[8 9]`, cost 3 | shape rejection | satisfied, exact pair binding |
| `[4 [[0 2] [[1 7] [0 4]]]]]`, subject `[0 0]` | atom 7, cost 3 | projection rejection | satisfied; inactive invalid projection gated |
| Same formula, subject `[1 0]` | native error | projection rejection | witness rows unsatisfied |

A further formula branches between `[[1 2] 3]` and `[1 [2 3]]`. Both have the
same flattened leaves; changing only the claimed association fails public
coordinate binding. Output topology is derived from the two formula arms before
any input/witness/output claim is supplied.

## Constraint review

For each carrier, Boolean tag and zero pair payload are explicit rows. An
atom-only schema constrains tag zero. An atom parent constrains both immediate
child tags/payloads to zero; applying the same invariant recursively makes all
absent descendants canonical. Output binding traverses the already allocated
schema, pinning every tag and payload, including absent descendants.

Branch selectors use the complete nonzero gadget (product, Boolean selector,
zero/nonzero implication and canonical inverse at zero). Atom requirements and
axis traversal requirements are multiplied by branch activity. Each evaluator
constructs canonical atom-zero when inactive. Invalid supported formula syntax
requires activity zero rather than manufacturing a valid active execution.
Valid opcodes outside the documented subset return `Unsupported`, including
when inactive; they are not falsely classified as a native runtime error.

Selected cost is the sum of activity-gated own/child costs. The disjoint two-arm
cost sum equals the cost of the selected arm. The checked maximum bounds the
integer interpretation below Goldilocks p, but an expensive inactive inverse
arm does not raise the required public execution budget. A cost of 3 is accepted
with budget 3 even when the compiled maximum is 67.

CCS rows are homogeneous. The all-zero candidate intentionally satisfies the
raw matrix relation, as it must; `verify_witness` rejects it through the mandatory
`z[0]=1` binding. A future proof adapter must authenticate **all** coordinates
returned by `public_coordinates` under the same witness commitment as the CCS.
It must not call raw `is_satisfied_by` and describe that as a complete statement.
Padding columns beyond allocated wires are not meaningful noun coordinates and
are not claimed to be canonical; absent **noun** descendants are constrained.

Allocation is charged before gates/carriers are appended. Formula and subject
validation have depth/node bounds before compilation, output depth is checked
before matrix allocation, witness length is checked before indexing, and output
claims are bounded/canonical before coordinate traversal. No allocation depends
on claimed output beyond the bounded traversal or on secret-dependent shape.

## Initial kernel receipts (before hash extension)

Command (no STARK prover):

```sh
cargo test --manifest-path zheng/rs/Cargo.toml --release --locked tagged \
  --features serde -- --test-threads=1 --nocapture
```

`/tmp/zheng-tagged-serde-tests.log`: **7 passed, 0 failed, 0 ignored**, 183 library
tests and 5 integration tests filtered out; execution 0.01 s, zero warnings.
This is a targeted receipt, not a claim that the entire Zheng suite was rerun.
The preliminary no-default-features run passed its then-existing six tests;
the final seven-test receipt above is authoritative for the completed module.
`rustfmt --check` on all four new Rust files and the export's `git diff --check`
also pass.

Coverage includes both branch choices, near-modulus nonzero conditions,
arithmetic/native equality, inverse/native equality, nested shape unions,
inactive malformed arithmetic, active atom-type errors, invalid axis and inverse,
wrong public input/output/cost/budget, changed tags/pair payloads/absent padding,
all-zero candidate, unsupported valid opcodes, excessive depth, noncanonical
atoms and wrong input/witness lengths. The same formula/shape regenerates exactly
equal sparse matrices regardless of which tested input selects an arm.

A separate fixture has **128 rows, 64 columns, 47 materialized wires**, and maximum
cost 71. All **376** single-coordinate `+1`/`-1` mutations across inputs
`0, 1, 2, p-1` fail the complete verifier without replaying witness recipes.
These mutations are regression evidence, not a mathematical proof of soundness
or a replacement for independent review of the constraint equations.

## Remaining necessary implementation

1. Independently review this kernel's constraint induction and resource policy.
   Existing production static-shape errors remain unchanged until a reviewed
   versioned adapter is integrated; the native examples above must then pass
   through the actual public/private verification entry points.
2. Extend beyond the now-supported literal-quoted continuation subset only with
   independently derived continuation bounds and dispatch constraints. Fully
   computed formulas remain unsupported; witness-selected matrix compilation
   is forbidden. Quoted continuations now exercise optional subject projections.
3. Add complete relations for call/state operations and
   bounded continuation dispatch. Do not replace unsupported algorithms with
   prover-only checks or describe this subset as arbitrary dynamic execution.
4. Specify a separately domain-separated production statement carrying exact
   noun topology; bind canonical input/output encodings, program/relation
   identity, selected cost and every public coordinate under the chosen proof
   protocol. Reuse a reviewed proof backend, preserving existing envelopes until
   deliberate migration and independent adversarial proof-level validation.


## Native structural hash extension — current receipt

The draft contract now includes structural axis0, pattern15 and full four-limb
identity equality. The exact existing `nox/rs/data/hash.rs` atom/parent framing
is reproduced with constrained Hemera state wires. No hash parameters were
changed; native nox sets `is_root=false`, so root finalization is deliberately
not invented at the top of a noun. Pattern15's additional plain permutation
and own cost25 match native. Atom equality also follows the native digest rule,
without assuming injectivity of the atom hash or using only the first limb.

The byte decomposition has both Boolean reconstruction and `<p` constraints.
The adversarial test supplies coherent alternate bit representations `x+p` for
`x=0, 1, 2^32-2`, recomputes **all** dependent gates, and verifies that precisely
the canonical-range row fails. This prevents alternate byte framing despite
identical field recomposition.

A second adversarial test corrupts an absent child's tag or payload and
recomputes all dependent hash states. The selected atom digest remains identical;
carrier constraints nevertheless reject the witness. Therefore hash tag
selection cannot conceal unconstrained padding. Dedicated equality tests hold
three digest limbs equal and change only limb four, checking false equality
against the actual matrices. Inverse-zero, public tags/cost/all four output
limbs, sampled round wires and the inherited all-zero statement checks also run.

Memoization uses monotonically assigned carrier IDs plus atom/pair operand-wire
identities. It does not use recycled pointer addresses or witness values. Unit
activity preserves carrier identity through `mask`, so repeated identity
consumers share constrained digests. The memoization regression verifies equal
wire identities and unchanged gate/row count on the second hash of a carrier.

Current command:

```sh
cargo test --manifest-path zheng/rs/Cargo.toml --release --locked tagged \
  --features serde -- --test-threads=1 --nocapture
```

`/tmp/zheng-tagged-hash-tests.log`: **14 passed, 0 failed, 0 ignored**, 183 library
and 5 integration tests filtered out; **0.06 s**, zero warnings. No STARK prover
or production proof protocol was invoked. This supersedes the initial seven-test
receipt above for the current experimental module. The inherited all-wire
mutation fixture now has45 materialized wires (unit-mask sharing removes two
copies), and all360 mutations reject; its dimensions remain128 rows/64 columns.

Measured padded dimensions (not inferred proving performance):

| Native comparison | Rows | Columns | Maximum native cost |
| --- | ---: | ---: | ---: |
| axis0 of pair `[0 p−1]` | 8192 | 8192 | 1 |
| pattern15 of pair `[0 p−1]` | 8192 | 8192 | 26 |
| axis0 of either association of a three-atom tree | 16384 | 16384 | 1 |
| pattern15 of either association of a three-atom tree | 16384 | 16384 | 26 |
| pattern15 of atom-or-nested-pair branch | 16384 | 16384 | 28 |

Native differential inputs include `0`, `1`, `2^56−1`, `2^56`, `p−1`; optional
atom/pair outputs and asymmetric nested trees; equal/unequal atoms and pairs;
different associations of the same leaves. Regenerating the optional relation
produces identical sparse matrices across tested branch selections. An18-atom
nested hash exceeds the existing gate budget and returns `Limit` before matrix
allocation, rather than claiming it has general unbounded noun support.

That checkpoint completed the identity consumers only. The later quoted static
composition extension is recorded below; bounded dynamic continuations, external
call/state relations and a
versioned reviewed proof adapter remain necessary. Hemera's separate external
cryptographic review gate is unchanged by functional native agreement.


## Ordering, words and quoted composition — current receipt

`word.rs` adds native opcode10 unsigned64 less-than (0=true, own cost64),
opcode11 XOR,12 AND,13 NOT and14 shift (own cost32). Every U32 operand is
multiplied by activity before its exact Boolean32 decomposition, so inactive
invalid ranges neither fail execution nor introduce free bit witnesses. Active
values above U32 fail rows. Shift uses five low bits in a checked barrel shifter
and forces zero when any higher shift bit is set; it never reduces >=32 modulo32.
The comparator uses the same canonical `<p` bits as native structural hashing.

Opcode2 supports a syntactically literal quoted RHS. The quoted continuation is
compiled against the **computed tagged subject**, rather than the old subject or
a witness-selected static shape. Its quote cost1 and compose own cost1 are both
included. A malformed quoted continuation is a gated native error. Other RHS
forms return Unsupported, even when a particular native input makes them return
a fixed formula. No production relation or proof format changed.

The native projection regression constructs `[flag optional]`, where `optional`
is atom7 at flag0 and pair[8 9] at flag1. Its continuation reads atom7 on the first
branch and the pair head8 on the second. Both pass with identical matrices. An
unguarded pair projection passes for flag1 and fails native execution and circuit
rows for flag0. Other composition cases cover mixed-shape identity, axis0 and
pattern15 on computed subjects, a word operation after composition, nested
quoted composition, and an inactive malformed continuation.

Current command is unchanged except log path:

```sh
cargo test --manifest-path zheng/rs/Cargo.toml --release --locked tagged \
  --features serde -- --test-threads=1 --nocapture
```

`/tmp/zheng-tagged-word-tests.log`: **21 passed, 0 failed, 0 ignored**, 183 library
and5 integration tests filtered out; **0.15 s**, zero warnings. No heavy prover.
This is the current targeted module receipt, superseding the earlier14-test
checkpoint. Formatting checks pass for every tagged Rust file.

Unsigned ordering covers the49 combinations of `0,1,2^32−1,2^32,2^63−1,2^63,p−1`.
Word comparisons cover all combinations of `0,1,31,32,0x80000000,0xffffffff`, plus
shift amounts33,63,64 andU32_MAX. NOT includes zero/all-ones. Active invalid-range
and pair-operand failures are contrasted with their inactive successful forms.
Every successful case verifies native execution again with the **exact** actual
cost, accepts that same public proof budget and rejects cost/budget substitution.

| Operation mutation fixture | Rows | Columns | Mutated materialized wires | Native cost |
| --- | ---: | ---: | ---: | ---: |
| unsigned64 less-than | 512 | 512 | 457 | 66 |
| XOR | 256 | 256 | 137 | 34 |
| AND | 128 | 128 | 105 | 34 |
| shift33 of U32_MAX | 1024 | 1024 | 590 | 34 |

All1289 one-coordinate mutations fail complete statement verification. The
mixed-subject guarded composition has256 padded rows and128 columns. These are
actual matrix dimensions and local constraint tests, not inferred proof timings
or a claim that all native programs now have relations.

Remaining general-execution work is computed continuation dispatch with public
bounds, complete external call/state binding, and deliberate versioned proof
integration plus independent review. The accepted subset now exercises static
compiler-like compositions while refusing witness-dependent formula selection.

## External Hemera FINAL5-to-live dependency review

The parent detected external sibling edits while the full Zheng suite ran. The
Zheng-only source inventory below does not cover those dependencies and must not
be interpreted as closure stability. Read-only comparison used
`/tmp/cyber-release-extracted-v7-final5/cyber-source/hemera` against live `hemera`.
No Hemera source or external work was modified by this review.

Raw differences in25 Rust files normalize to15 formatting-only files,9 inspected
semantic/comment changes, and1 new test file. Normalization used `rustfmt --emit
stdout --config skip_children=true` on both copies; normalized differences are
retained under `/tmp/hemera-final5-semantic-review/`, with `summary.json`.
Round constants, encoding, StepSponge, fixed vectors, GPU wrapper, CLI and benchmark
code are exactly equal after normalization. Field arithmetic differs only by
removal of a duplicate test import.

The remaining runtime changes are equivalent arithmetic assignment (`+=` uses
unchanged `AddAssign`, which delegates to `Add`), an enumerate-based bootstrap
constant fill, iteration over the same16 internal constants, tuple grouping of
private helper parameters, and chunk-count `div_ceil` replacing pre-addition
rounding. The last change avoids overflow near `usize::MAX`; it changes hostile
length handling, not hashes of representable input slices. CDC debug assertions
use range/`is_multiple_of` helpers. StreamDecoder gains a redacted Debug impl.
No existing public signature or caller requirement changed.

`permute_with_constants` now documents the fixed144-constant profile. Inputs
shorter than144 still panic, but the partial-round slice check can panic before
previously processed partial rounds. Trailing constants remain ignored. This is
invalid-input state-mutation timing drift, not a supported hash/profile change.
The new2-test profile regression verifies both length boundaries.

Research-only `rational_search.py` exposes a coordinate-count option; the default
remains4, matching its prior function default. Its output labels and source-lock
manifests change. They are research artifact identities, not runtime root or
transcript identities. The updated proof/research source-lock hashes match live
files; this does not substitute for evaluating their research/security claims.

Command:

```sh
CARGO_BUILD_JOBS=2 RAYON_NUM_THREADS=4 cargo test \
  --manifest-path hemera/Cargo.toml -p cyber-hemera --release --locked \
  --test vectors --test constant_profile -- --test-threads=1
```

`/tmp/hemera-final5-compatibility-tests.log`: **8 passed, 0 failed, 0 ignored**,
zero warnings (2 profile tests +6 unchanged fixed vectors). Together with the
21 tagged native/CCS comparisons, the reviewed changes show no changed Hemera
structural digest/root/transcript calculation or tagged gadget incompatibility.
This finding is limited to this inspected Hemera diff; it does not certify the
other externally changed siblings or unchanged source/archive provenance.

## Full live Zheng workspace validation

Completed after the tagged ordering/word/composition checkpoint:

```sh
CARGO_BUILD_JOBS=2 RAYON_NUM_THREADS=4 cargo test \
  --manifest-path zheng/Cargo.toml --release --workspace --features serde \
  --locked -- --test-threads=1
CARGO_BUILD_JOBS=2 RAYON_NUM_THREADS=4 cargo check \
  --manifest-path zheng/Cargo.toml --release --workspace --features serde --locked
```

`/tmp/zheng-tagged-full-workspace.log`, exit0: **211 passed, 0 failed, 0 ignored,
0 filtered** across all test binaries:204 library tests,5 execution-adversarial
integration tests and2 CLI tests. Doc-tests contained0 tests. Zero compiler
warnings. The library run took1011.45 s; it includes both ordinary exhaustive
`every_bit_of_the_wire_is_checked` and `every_byte_of_a_two_group_wire_is_checked`.
Neither was skipped or reduced. No Trisha STARK or ignored heavy proof gate ran.
`/tmp/zheng-tagged-full-check.log`, exit0: complete workspace release+serde check
passed with zero warnings (5.96 s).

The63-file Zheng Rust/manifest/lock inventory captured during this run remained
unchanged at completion; it includes tracked and untracked source files. Exact
comparison receipt: `/tmp/zheng-tagged-full-stability.json`; inventory digest
`ca104f713885508faef9200b2882dff7808a058c38da203ee247ddfa37ebc7ba`.
This inventory was captured while the exhaustive test was running, not as a
pre-build archive attestation. It excludes sibling dependencies and documentation;
external dependency/source provenance changes require their own review. The
Hemera compatibility review above covers the specific FINAL5-to-live changes
inspected here. No source-closure stability is inferred from the63-file check.

Post-implementation review rechecked branch activity propagation, source-only
composition dispatch, selected integer costs, exact output topology, canonical
bit ranges, total inverse constraints, all-four-limb equality, cache key lifetime
and complete public-coordinate binding. No new concrete defect was found in
the implemented subset. Tagged Rust formatting checks pass; each source file is
below500 lines. Existing production relation/proof envelopes are untouched; the
remaining dynamic continuation/call/state/protocol-integration work stays open.
