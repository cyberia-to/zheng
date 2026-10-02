# Disclosed evaluation DAG validation

The source is based on `24a87077e7e2853d402b4dfc83eb9f9aa2f78ea7`.
`review-source.json` identifies every final changed source file by SHA-256 and
pins the nox, Hemera, strata and lens dependencies. This report travels in the
same commit as those exact source bytes. `review-commands.json` retains command
arguments, environment, UTC start, duration, exit code and output SHA-256.
The earlier source snapshot and commands remain in `source.json` and
`commands.json`; the final source adds adversarial test cases only.

## Results

The following counts refer to that final source snapshot and the named raw
logs. Commands ran with Rust 1.89.0 and `CARGO_BUILD_JOBS=2`.

| Command | Result | Evidence |
| --- | --- | --- |
| `cargo test -p zheng --locked --release execution::disclosed::` | 23 passed: 10 noun-memory and 13 evaluation-DAG tests | `review-default.log` |
| Same command with `--all-features` | 23 passed, none failed or ignored | `review-all-features.log` |
| `cargo test -p zheng --locked --release --test disclosed_evaluation_allocation` | 1 passed; actual initial allocation and growth failures preserve state and permit retry | `allocation-default.log` |
| Same allocation command with `--all-features` | 1 passed | `allocation-all-features.log` |
| `cargo check -p zheng --locked --all-features --all-targets` | Passed with zero warnings | `review-check.log` |

The allocation tests ran before the final adversarial-only changes; their
integration-test and production-source hashes are identical in both manifests.
No compiler warnings appear in the retained acceptance logs. Filtered tests
are shown as filtered in raw output and are excluded from these pass counts.
The early `targeted-default.log` is exploratory, superseded by the source-pinned
final runs; its intermediate source snapshot was not retained separately.

## Covered properties

Native differential tests cover every pure opcode's result, exact charged cost,
exact/excess budgets and exact/one-below frame limits. Dedicated cases cover
axis-zero versus native hash, field boundaries, word shift behavior, computed
continuations, duplicate noun occurrences and repeated evaluation premises.
One repeated-premise case compares derived expanded occurrences and steps with
the native observer, including terminal completion and evaluator checkpoints.

Adversarial cases change premise keys, arity, order, birth frontier, selected
branch, computed continuation object and formula independently, result topology,
every final particle limb, exact cost, budget and frame bounds. Invalid types,
inverse zero, malformed/service invocations, checked metric overflow and
one-below resource limits reject. Unselected malformed/service/dynamic formulas
and saturated cached bounds preserve their cheap selected execution. Allocation
refusal uses a System-delegating test allocator confined to its integration-test
binary; both initial allocation and growth return errors without partial records.

The root agent independently read the specification and all production rule,
primitive and storage code. It reported no correctness finding and requested
the independently varied continuation keys and selected-arm rejection tests,
which are included in the final source-pinned runs. This is a separate code
review, not an independent rerun of these logs.

## Scope

This delivery validates finite successful semantic DAGs over a fixed validated
noun-memory view. The component has no transport, compiler-job binding or Joy
dispatch. Whole compiler proving, bounded stream composition, physical LIM1/GC
claims and SH7/SH8 acceptance remain open. No proof-size, whole-compiler speed,
succinctness or privacy claim is derived from these component tests.
