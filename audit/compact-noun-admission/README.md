# Compact noun admission

`Memory::append_value` accepts disclosed atom/pair data and derives its particle
and Cost through the same private validation path as claimed definitions. A
future stream can omit those redundant fields. Root binding remains explicit;
this change adds no execution proof or transport format.

Validation used Zheng base `b6ee58895ad99fc08e2add7870f9b958171b0a75` plus the
four exact files in `source.json`. `receipt.json` retains commands, original log
hashes and exit statuses. Every command explicitly used `rustup run 1.89.0 cargo`
with locked offline dependencies and two build jobs.

| Cargo command suffix | Result |
|---|---|
| `test --workspace --release --locked --offline -- --test-threads=2` | 242 passed, zero failed, one existing ignored |
| `test -p zheng --release --locked --offline --all-features disclosed::memory -- --nocapture` | 11 passed |
| `test -p zheng --release --locked --offline --all-features --test disclosed_memory_allocation -- --nocapture` | two actual allocation-failure/retry tests passed |
| `check --workspace --all-targets --release --locked --offline --all-features` | passed, zero warnings |

All command logs contain zero warnings. Existing native differential fixtures
now compare claimed and compact admission record-for-record, including every
Cost rule and saturated/full-u64 bounds. New cases reject noncanonical values,
future/self references, exceeded capacity and incorrect expected root bindings.
The isolated allocator test exercises first allocation and growth refusal for
both public entries. Independent read-only review found no correctness issue;
`review.json` binds the reviewed files. No new performance measurement is made.
