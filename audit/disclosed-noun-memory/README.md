# Compact disclosed noun memory

The experimental table checks every noun header, four-limb particle and cached
Cost before insertion. Pair and Cost reads resolve through prior validated
records. Bounded views restrict reads to a caller-selected frontier. This is the
memory component for a future public semantic certificate; execution transitions,
production Joy dispatch and the SH7/SH8 gates remain open. The existing CCS
component and its unresolved-read guard are unchanged.

Source is Zheng base `633e5ba980db94ca10d9d6b67cf24d9d3aef63a7` plus the exact
local files in `final-source.json`. These measurements preceded this feature
commit and are local development evidence. The source maps bind every changed
Rust/spec file and the clean sibling revisions. `receipt.json` retains exact
commands, exit statuses and original log hashes. Rust was selected explicitly
through `rustup run 1.89.0`; Cargo used locked, offline dependency resolution.

## Checks

Commands below are the Cargo suffix after that rustup prefix, in the feature
worktree. Counts are parsed from the retained logs, with no ignored test counted
as passed.

| Command | Source map | Result |
|---|---|---|
| `cargo test --workspace --release --locked --offline -- --test-threads=2` | `final-source.json` | 240 passed, zero failed, one existing ignored |
| `cargo test --workspace --release --locked --offline --all-features -- --test-threads=2` | `source.json`, initial test set | 244 passed, zero failed, one existing ignored |
| `cargo test -p zheng --release --locked --offline --all-features disclosed -- --nocapture` | `final-source.json` | ten component tests passed |
| `cargo test -p zheng --release --locked --offline --all-features --test disclosed_memory_allocation -- --nocapture` | `final-source.json` | actual allocation/refusal/retry test passed |
| `cargo check --workspace --all-targets --all-features --release --locked --offline` | `final-source.json` | passed, zero warnings |

The full all-features run compiled the initial eight component tests. Additional
adversarial cases and the isolated allocator test were added while its existing
exhaustive wire-mutation tests ran. Final targeted all-features, the default
workspace suite and the final all-targets check cover the final source. The
earlier logs remain available and are not relabeled as that final test set.

Coverage includes native differential identities and all Cost rules, canonical
field boundaries, every particle limb, ordered children, strict prior indices,
same-content duplicate occurrences, changed expected roots, restricted read
frontiers, both Cost limbs, Exact/Dynamic substitution, smaller Dynamic branch
arms, non-saturated Costs above the field modulus and u64 saturation. A separate
test executable refuses real first allocation and reallocation through a
thread-local System allocator wrapper, checks unchanged memory and retries.

Independent source review checked arithmetic, crypto framing, locality, bounds,
adversarial inputs, API scope and testability. `review.json` binds the reviewed
file hashes and resolved coverage findings. The reviewer read the retained logs
but did not independently rerun the tests.

## Measurement

`cargo run -p zheng --example disclosed_memory_cost --release --locked --offline
-- 50000` at the exact source map `measurement-source.json` generated 50,000 native
atoms and 49,999 native pairs, then admitted all 99,999 definitions through the
new verifier. `measurement.log` records one local observation:

| Quantity | Observed value |
|---|---:|
| Validated record storage | 64 bytes per slot |
| Requested record buffer | 6,399,936 bytes |
| Native fixture construction/extraction | 582,505,625 ns |
| Complete table admission | 576,565,334 ns |

The buffer count excludes the source definitions, allocator bookkeeping and
small table object. It is neither process RSS nor a serialized proof size.
This fixture establishes bounded noun/Cost admission only. It does not predict
whole-compiler unique noun counts, certificate size, proving time or verification
time. A complete execution relation and actual compiler census precede those
claims.
