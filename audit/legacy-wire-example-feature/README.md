# Declare the serialization-dependent example feature

At clean Zheng `c753f5ae055d3f4a43847877521f119d3b40dd39`, the full default
workspace test command failed with `TraceProof: serde::Serialize` at
`rs/examples/legacy_wire_cost.rs:29`. That example serializes its proof, while
`TraceProof` serialization is gated by `serde`. Its target lacked the matching
Cargo feature requirement.

The repair adds only `required-features = ["serde"]` to an explicit
`legacy_wire_cost` example declaration. Cargo.lock and dependency versions are
unchanged. Default builds select supported targets; enabling `serde` still
compiles the serialization example.

`receipt.json` binds the original source identities, exact minimal diff,
commands, dependency revisions, clean statuses, and lossless compressed logs.
The repaired base was tested in a separate real worktree with only
`rs/Cargo.toml` modified:

- `cargo check --workspace --all-targets --all-features --release --locked --offline`
  passed with zero warnings and includes the serde-enabled example.
- `cargo test --workspace --release --locked --offline -- --test-threads=4`
  passed: 215 tests, zero failures, one existing ignored test, zero warnings.

Both commands use the explicit `CARGO_TARGET_DIR` and working directory in the
receipt. The failed original command/log remains retained. These measurements
precede the fix commit and refer to base c753 plus the recorded manifest diff.
