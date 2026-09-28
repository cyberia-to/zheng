# Local noun/Cost CCS component

This local development unit adds an internal component to the existing tagged
relation builder. It constrains one candidate noun's native Hemera header and
cached Cost using six explicit read premises. Production finalization rejects
unresolved reads. The component tests make all seven records public premises
and use the existing full-witness direct CCS backend. This evidence covers
local constraints; authenticated global memory, semantic transitions, Joy
proof dispatch, succinctness, zero knowledge and SH7 remain outside this unit.

The source capture is based on Zheng `c753f5ae055d3f4a43847877521f119d3b40dd39`
plus the exact uncommitted files in `frozen-source.json`. The separate manifest
repair declares the existing `legacy_wire_cost` example's `serde` requirement;
`manifest-repair.json` binds its exact change. Neither capture is represented as
a committed release input. `family-created.json` identifies the clean, real
sibling worktrees used by the final gates, including Nox
`71b5860219f0e0810200946e4445e5fdf54269dd` and Tade
`c1d81c75725df0a666c36d81ef33c3a60eb007f3`.

## Evidence and limits

The owner contract declared 32768 operation wires, 32768 constraint rows and
at most 65536 padded witness coordinates before measurement. A component has
127 input coordinates and one candidate plus six read records. The existing
backend also enforces its sparse-entry bound. The exact-cap and one-below tests
exercise successful construction and fail-closed partial construction; a
second component attempt and ordinary finalization with pending reads reject.
No cap was increased.

The fourteen component tests cover all eighteen native Cost opcode cases and
malformed-body fallback, u64 saturation above the field modulus, independent
header/selector/digest/auxiliary corruption, mandatory-read removal, local
same-particle conflicting Cost, canonical atom aliases and fixed matrices
across values/topologies. An unused read Cost may change when its explicit
public premise changes: this is a positive boundary of the conditional local
interface. It cannot discharge pending memory obligations. Backend attacks use
matching forged public values as well as independent wrong public coordinates,
so rejection is checked beyond disagreement with the honest input vector.
The zero-vector attack tests the backend's mandatory constant-one binding.

Complete command arrays, source/dependency identities, exit statuses and raw
log hashes are retained in the JSON receipts. Each `.log.gz` decompresses to
the original captured log bytes; warning lines and unsuccessful attempts are
preserved. Timings are single local observations, not comparative performance
claims. Serialized proof size describes the existing public full-witness
format, not a succinct or private proof.

## Final gates and measured component

The commands below ran in the real clean dependency family recorded by
`repaired-gates.json`, with the exact 14-file source map in `final-source.json`
(SHA256 `62f17fddef1ac64f14c7b8e86a34c3692d159e935d7cf19981d2364657150dff`).
The captures truthfully retain base c753 plus the local changes; the manifest
repair was subsequently committed as `a8d562a92ac538cc136474e240fc0ce5bb9aea8b`
and merged as `ebf124efa6fa29194b3f3fe5205e9956b82b915e`.

| Recorded command | Result |
|---|---|
| `final-component-check`: `cargo check --workspace --all-targets --all-features --release --locked --offline` | passed, zero warnings |
| `final-component-default`: `cargo test --workspace --release --locked --offline -- --test-threads=4` | 229 passed, 0 failed, 1 ignored, zero warnings |
| `final-component-all-features`: `cargo test --workspace --release --locked --offline --all-features -- --test-threads=4` | 236 passed, 0 failed, 1 ignored, zero warnings |
| `final-component-serde`: `cargo test -p zheng --release --locked --offline --features serde node_cost_tests -- --nocapture` | 14 passed, 0 failed, zero warnings |

Counts describe separate runs with overlapping tests and are not summed.
`format-owned.json` records the passing explicit-file formatting check.
Independent read-only core review is retained in `independent-review.json`.

The `final-component-serde` command measured 27606 raw rows, 26014 operation
wires, 213565 sparse entries, and a padded 32768 by 32768 instance. Its witness
field payload is 262144 bytes; this is not a bound on host memory. The public
full-witness postcard proof is 294371 bytes. Single-run times were 5523834 ns to
build, 977209 ns to generate the witness, 364205375 ns to prove, and 351750916 ns
for complete verification. `receipt.json` and the exact raw log retain these
values. The fixed local component fits the original cap with 5162 raw rows of
headroom; authenticated memory composition has not been measured here.

## Retained unsuccessful work

The first exploratory focused run had two test-assumption failures. The atom
alias attack located a binding row in the wrong sparse matrix; the corrected
attack uses A=ONE, B=claimed-minus-derived particle, C=0 and leaves exactly the
canonicality row unsatisfied after updating the forged public digest. The
other test wrongly expected every pair read Cost to affect local derivation;
branch body/rest read Costs are explicit, sometimes unused premises. The final
suite includes their positive boundary and separate conflicting-Cost attacks.
No production constraint was removed to make those tests pass. Early prototype
logs are retained as exploratory history, without assigning the later frozen
source identity to their unretained intermediate source state.

The unmodified clean base's default workspace command failed because the
existing `legacy_wire_cost` example serialized `TraceProof` without enabling
`serde`. The small manifest repair is tested separately before applying the
frozen component. The original failure is retained rather than excluding that
example from the claimed full gate.

An overbroad `cargo fmt --all` at 2026-09-28 04:37:46 UTC also formatted shared
Nox and Tade dependencies. Those writes were identified before final validation.
Root recovered only the captured formatting diffs after establishing exact
preimages; all affected files match their Git blobs and both worktrees are
clean. The recovery receipts and Tade formatting reproduction are retained.
The six pre-existing Lens formatting changes were untouched. All subsequent
acceptance gates use the new real worktree family; formatting checks address
only the explicitly owned Rust files with `skip_children=true`.
