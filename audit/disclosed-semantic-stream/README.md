# Bounded disclosed semantic stream validation

This change starts at `e4959de00d3d12727877100e304d8dd155b0b0f5`, integrating
the disclosed noun-memory and finite evaluation-DAG components. `source.json`
pins every changed source/spec file by SHA-256 and all local sibling dependency
revisions. Those dependencies were clean. The final source bytes travel with
this report in one commit. `commands.json` retains exact arguments, environment,
UTC start, elapsed time, exit code and raw-output SHA-256 for the final gates.

## Results

The following results refer to `source.json`. All commands use Rust 1.89.0,
`--locked --offline`, and `CARGO_BUILD_JOBS=2` in the isolated semantic worktree.

| Command | Result | Raw evidence |
| --- | --- | --- |
| `cargo test -p zheng --release --lib execution::disclosed::` | 40 passed: 11 memory, 13 finite DAG, 16 staged stream | `default.log` |
| Same test command with `--all-features` | 40 passed, none failed or ignored | `all-features.log` |
| `cargo test -p zheng --release --test disclosed_stream_allocation` | 1 passed | `allocation-default.log` |
| Same allocation command with `--all-features` | 1 passed | `allocation-all-features.log` |
| `cargo check -p zheng --all-features --all-targets` | Passed with zero warnings | `check-all-targets.log` |

No warnings appear in these retained gate logs. Filtered tests are excluded
from pass counts. `initial-stream.log` and `extended-stream.log` are exploratory
focused runs, superseded by the final source-pinned gates; the intermediate
source of the initial run was not retained separately. These are component
checks, not a rerun of every historical proof-system test or a release receipt.

## Coverage and review

The differential fixture checks all pure opcodes against both pinned nox
sequential evaluation and the independent finite DAG verifier. Every semantic
event receives a newly validated noun table with remapped indices; finish
tables contain only the reachable result. Parent object/formula bodies can
therefore disappear before their primitive finalizer runs. Tests compare result
particles, exact cost, expanded occurrences/steps and logical invocation height.

Cache tests retain checked atom and pair facts across noun resets and explicit
slot replacement, reject empty/stale/out-of-range generations and changed keys,
and charge a repeated child completely on each reuse. A nested-context case
checks current stack depth plus the cached derivation's entire height at the
exact frame limit and one below it. Generation overflow is reached using a
private test fixture; it is not claimed as a measured sequence of real evictions.

Adversarial cases change each terminal particle limb, exact cost, budget, frame
bound, selected branch, both computed continuation keys, every hash-data limb
and hash topology. Wrong output rejects for every pure opcode. Other cases cover
noncanonical root particles, out-of-range noun indices, malformed formulas,
invalid primitive types, inverse zero, wide words, unsupported evaluated tags,
truncation, excess events/roots and checked metric overflow from compact shared
derivations. Cheap selected execution remains valid with saturated, Dynamic,
service and malformed code in the unselected branch.

The isolated integration-test allocator delegates valid operations and all
deallocations to `System`. Thread-local refusal reaches the actual first stack
allocation and second cache allocation separately, then a fresh construction
succeeds. A complete cons-of-repeated-quote sequence, including cache reuse and
terminal binding, succeeds while further allocations are refused. This directly
tests that sequence; it does not measure arbitrary allocator overhead or claim
fault injection into every possible host allocation.

Review questions addressed by implementation and tests:

- Can a parent accidentally read a reused noun ID after reset? Activations
  retain only complete particles, primitive facts and metrics; no IDs or views.
- Can an unchecked or stale cache summary enter the proof? Summaries have no
  public constructor/import, slots hold only locally checked completions, and
  reuse checks generation and the complete pending key.
- Can cache reuse evade budget/depth accounting? Each use adds the full checked
  metrics, with checked integer arithmetic and the current stack depth.
- Can partial failure later produce a valid root? Every semantic event error
  poisons the session, including errors after a cache write or child completion.
- Does result equality substitute for primitive verification? The checker
  independently applies primitive equations and checks authenticated output
  topology or complete particles as the rule requires.

Production processing is deterministic and iterative. Each semantic event
touches one top activation and at most one cache slot; Enter axis navigation
has at most 63 hops. Native hash uses a fixed-size permutation. Noun validation
is accounted separately by the noun-memory component. Construction reserves
bounded buffers fallibly; event processing adds no buffers. The public input
is disclosed, so this component makes no secrecy/zero-knowledge claim.

The root agent separately reviewed the final specification, production state,
primitive and staging code, allocator test and adversarial tests. It confirmed
the reviewed production/allocator bytes match `source.json` and reported no
correctness finding. This is code review, not an independent rerun of the
retained test logs.

## Scope

This component checks one successful pure semantic derivation with bounded
active storage, generation-checked reuse and caller-bound root particles/cost.
It has no wire decoder, contextual job binding or production Joy dispatch.
Transport owns complete noun resets, context, framing, compression and trailing
byte rejection. Physical allocation/GC/deadline/LIM1 execution claims remain
outside this statement. Logical invocation height includes leaves and must not
be confused with raw live continuation depth.

No whole-compiler capacity, proof-size, throughput, privacy, succinctness or
SH7/SH8 acceptance is inferred from these tests. End-to-end streamed compiler
certificates and Joy integration require their own source-pinned evidence.
