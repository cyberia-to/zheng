# Node dependency profile — 2026-09-23

This candidate makes the committed Zheng dependency usable with the Cyber
node's Lens 0.2 / Nox 0.3 dependency closure. It starts at `ef3370f` and adopts
the existing 0.4 manifest alignment already required by the committed CLI and
the BBG candidate. It changes no production Rust proof algorithm.

## Included boundary

- Existing state root helpers, `LookOpening`, accumulators, native decider and
  bounded public execution v1 remain available.
- Legacy Tensor gadget documentation and tests identify their actual scope:
  equality and squeeze-row primitives. They do not authenticate current Lens
  openings. `commit` already rejects recursive axis/look openings with
  `UnsupportedRecursiveOpening`; this gate remains intact.
- Stale positive tests expecting that retired recursive path to succeed are
  replaced by supported direct axis execution, authenticated opening
  substitution rejection, nonempty linear folding and binding-group
  substitution tests. Honest recursive look input is explicitly rejected.
  Forged opening/root/value cases still assert rejection. No test is ignored.
- The existing `legacy_wire_cost` example requires `serde`, matching its
  `TraceProof` serialization use. Default all-target builds therefore work
  without globally enabling optional serialization.

The owner checkout is untouched. Its new private/state/tagged execution
modules, branch-activity and budget relation rewrite, associated tests and
research documents stay outside this node candidate. Those capabilities
need a separate coherent proof-runtime review; a node dependency build
does not establish their readiness. In particular, new Joy private/state
artifacts require that separate source profile.

## Validation

Run in an isolated companion-repository checkout with the reviewed Lens and
Nox candidates and the existing Cargo lockfile:

- `cargo test --workspace --locked`: 163 library, 5 adversarial integration
  and 2 CLI tests passed; none ignored.
- `cargo check --workspace --all-targets --locked`: passed, zero warnings.
- `cargo check --workspace --all-targets --features serde --locked`: passed,
  zero warnings, including the serialization-dependent example.
- `cargo run --release -p zheng --example legacy_wire_cost --features serde
  --locked`: passed. The one-group fixture has 7,879 bytes / 63,032 mutation
  cases; the two-group fixture has 14,249 bytes / 28,498 mutation cases.
- `cargo test --workspace --release --features serde --locked`: 169 library,
  5 adversarial integration and 2 CLI tests passed; none ignored. This includes
  all 91,530 wire mutation attempts in both exhaustive wire tests.
  The earlier debug run was stopped because of its runtime; no mutation test
  was disabled or filtered from the replacement release run.

Lens source: `a5f57486ea5f443c2c46c8601ab84827ac69453f`.
Nox source: `1f2d9ef0af36392e24e761e9ac823e9dff87ab81`.

After aligning dependencies and updating the standalone gadget tests, the
first library run still produced 12 failures in the original top-level tests,
all in stale recursive-opening assumptions or empty legacy gadget results.
The corrections above preserve the public refusal boundary and test the
working paths directly. They do not restore recursive opening support or
establish production cryptographic security.
