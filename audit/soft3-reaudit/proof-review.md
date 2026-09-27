# Native private proof correctness and privacy review

Reviewed Zheng `2a9e9ccc83fed4a39e0d7c81c8b4034b223edba6` with nox
`c9f7486a74fe81bfc194b598da40f6343ecb2ef1`, strata
`d2eb1763b8caf04e6c7647ac6fe99761519c2ef9`, and Hemera
`a931a0a8e7ed369852ce0f8bc6451a59745ee692`. These revisions are the inputs to
every command and observation below. The new test file is an audit probe over
those unchanged implementation revisions. Host: macOS aarch64, Rust 1.95.0.

Scope: `rs/src/execution/zk/`, private statement preparation, static nox CCS
relations, state selection, cost/output bindings, and relevant field/hash owners.
Joy artifact authentication and deployment policy are reviewed separately.

No forged acceptance, proof-transcript witness disclosure, or native execution
mismatch was found in this review. The baseline has two local privacy hardening
gaps and one stale API comment. The follow-up below removes the measured inverse
shortcut and corrects the comment; broader local hardening remains open.
This is an implementation review with regression experiments;
it provides no independent cryptographic certification or complete VM coverage.

## Findings

### P2: private witness generation exposes secret-dependent local timing

At `rs/src/execution/relation.rs:125`, `Op::Inverse` skips field inversion when
the evaluated secret-derived linear expression equals zero. An observer capable
of measuring local witness generation can distinguish secret cases even when
the public program, output, and nox reduction count are identical.

Reproduction: `measure_equal_statement_witness_timing` in
`rs/tests/reaudit_private.rs`. Its formula compares a private call result with
zero, then discards that comparison through a static continuation returning zero.
Secrets zero and eleven produce the same asserted output/cost pair. Each sample
repeats witness generation 100,000 times. The diagnostic switches ordering and
records three samples for each secret; observed run:

| Sample | Secret | Total witness-generation time |
|---|---:|---:|
| 0 | 0 | 16,582,500 ns |
| 1 | 11 | 47,152,250 ns |
| 2 | 11 | 46,703,375 ns |
| 3 | 0 | 15,173,750 ns |
| 4 | 0 | 15,420,708 ns |
| 5 | 11 | 46,779,250 ns |

Command:

```sh
CARGO_TARGET_DIR=../target-proof-review cargo test -p zheng --release --locked --offline --features serde --test reaudit_private measure_equal_statement_witness_timing -- --ignored --nocapture
```

The timing probe is explicitly ignored by ordinary tests; portable correctness
does not depend on a noisy timing ratio. No end-to-end remote timing attack was
demonstrated. Related exposures are the secret activity branches at
`relation.rs:99` and `relation.rs:112`, and hidden namespace/index table accesses
at `private_state.rs:100`. The transcript's zero-knowledge property does not
protect a colocated observer of the proving process.

Proposed fix: remove the avoidable inversion shortcut (the field's inversion
routine already maps zero to zero), then explicitly define and test the local
side-channel threat model. Full constant-time private-state generation also
requires oblivious table access and field/runtime review; changing one branch
alone cannot justify a constant-time claim.

### P2: private preparation and PRG state have incomplete memory erasure

`rs/src/execution/private.rs:59` creates an ordinary secret field vector;
`private.rs:77` copies the witness into an ordinary `Vec<u64>`. The original
`CCSWitness` also has ordinary `Vec` destruction. The state path does the same
at `private_state.rs:87` and `private_state.rs:118`.

The backend erases owned seed and view buffers, but the PRG tapes created at
`rs/src/execution/zk/views.rs:31` and `views.rs:76` are Hemera `OutputReader`
values. `hemera/rs/src/sponge.rs:352` stores the sponge state and squeeze buffer
without a wiping `Drop` implementation. Copies and temporary stack values are
also outside the existing best-effort erasure boundary.

This is source-confirmed incomplete erasure, not a demonstrated remote memory
read. Exploitation requires memory disclosure, a dump, or another local memory
observation capability. Proposed fix: use explicitly secret-owned witness
buffers with wiping destruction and add an owner-level wiping interface for
Hemera streams. Preserve public `CCSWitness` compatibility while avoiding raw
secret clones in the private path. Document residual caller/runtime copies.

### P3: public prover API comment still says private proving is unavailable

`rs/src/execution/statement.rs:201` says the separate private protocol remains
unavailable. Native `zk::prove` and the private preparation APIs now implement
that path. The comment should link the implemented private protocol and keep
the public API's disclosure contract clear.

## Protocol and binding review

The arithmetic multiplication and two-view replay match the finite-ring linear
decomposition in [ZKBoo, sections 4.1.1–4.2 and Appendix A](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_giacomelli.pdf).
Verification checks every CCS residual, the constant coordinate, and all public
coordinates. It reconstructs the complete first message before checking the
global Fiat–Shamir challenges. Relation, statement, repetition, and party domains
are bound. The fixed repetition count gives the stated interactive error bound;
the noninteractive protocol additionally relies on its specified random-oracle,
Hemera commitment, and pseudorandom-stream assumptions. Compression does not
allow independently chosen hidden outputs after an accepted challenge.

Private statements reconstruct the relation from the canonical public program;
public input, output, selected cost, and budget are checked together. State
relations constrain active root/namespace/index/value selections against the
supplied public tables. Authenticating those tables against the external BBG
certificate remains an explicit owner obligation. A proof cannot conceal
information already exposed by the result or selected reduction count.

## Verification evidence

Run commands from the Zheng repository with
`CARGO_TARGET_DIR=../target-proof-review`. All listed commands used
`cargo test -p zheng --release --locked --offline --features serde` followed by
the exact selector below. Compiler output contained no warnings.

| Selector | Result | Coverage |
|---|---|---|
| `--test reaudit_private` | 3 passed, 1 timing diagnostic ignored | 1,152 generated native/CCS executions; generic CCS degrees 0, 1, 2, 3, 16; sparse cancellation; dimension and expanded-work attacks |
| `execution::zk` | 8 passed | Constant pin, wrong witness bypassing honest-prover guard, relation/statement/public substitutions, every opened pair, malformed/spliced/truncated/noncanonical payloads, serde length bounds, finite-ring simulator distribution |
| `execution::relation::` | 18 passed | Arithmetic, words, comparisons, inverse errors, static continuation, branch activity, structural hashing, digest/output mutations, generated compiler fixture |
| `execution::private` | 2 passed | Hidden namespace/index selection and forged root/provider result |
| `execution::call_tests` | 3 passed | Secret stream order/count, actual call continuation, inactive calls/invalid words |

The new differential probe generates 64 deterministic formulas and evaluates
each with six public inputs and three secret values. It checks native success
versus constraint satisfiability, then exact output and selected cost. It covers
field/word boundaries, private calls, branching, and static composition. It is
bounded regression exploration, not exhaustive proof of all formulas.

Logs for this session: `/tmp/zheng-reaudit-private.log`,
`/tmp/zheng-reaudit-backend.log`, `/tmp/zheng-reaudit-relation.log`,
`/tmp/zheng-reaudit-state.log`, `/tmp/zheng-reaudit-calls.log`, and
`/tmp/zheng-reaudit-timing.log`. The unchanged long-running legacy serde mutation
suite was not rerun by this review.

## Twelve-pass disposition

| Pass | Result and practical limit |
|---|---|
| 1 Determinism | Relation/binding/wire encoding deterministic; proof randomness explicitly comes from OS entropy. No witness-derived relation structure found. |
| 2 Bounded locality | Relation dimensions, sparse work, degree, gates, input/output counts, and proof bytes bounded before admitted processing. |
| 3 Arithmetic | Finite-field operations, canonical bit constraints, residual construction, and native output/cost probes passed. |
| 4 Crypto hygiene | Transcript checks passed review; local timing and incomplete erasure findings remain. |
| 5 Types/invariants | Verifier reconstructs public relation. `PublicStateTables` requires owner authentication; raw construction is not authenticated state. |
| 6 Errors | Malformed/prover failures return generic errors; no secret value found in private error messages. |
| 7 Adversarial input | Canonical fixed-width parsing, exact relation dimensions, work caps, truncated and length-bomb probes fail closed. |
| 8 Architecture | Native protocol uses Goldilocks/Hemera and nox CCS; no Neptune/Triton/Trisha proof engine in this path. |
| 9 Readability | Protocol domains and owner obligations explicit; stale public API comment identified above. |
| 10 Compactness | Replaying views twice trades CPU for bounded peak private memory. No redundant cryptographic layer required for acceptance. |
| 11 Performance | Proof and verification scale linearly with the admitted relation times the fixed repetition count. No succinctness or production latency claim inferred. |
| 12 Testability | Independent differential/edge probes supplement existing mutation, false-witness, and simulator tests. Independent cryptanalysis remains separate work. |

## Narrow hardening follow-up

The reviewed working patch over base `2a9e9ccc83fed4a39e0d7c81c8b4034b223edba6`
always computes the inverse, and corrects the public API comment. These changes
are local until committed; the implementation files identify the measured input:

| File | SHA-256 (`shasum -a 256 FILE`) |
|---|---|
| `rs/src/execution/relation.rs` | `6e4d50ae29f8b93d2350e27a5642896026097e54909099156b4738edadd769f2` |
| `rs/src/execution/statement.rs` | `0e11ed7ba6414584f702c886d41c0878fb20265cc75cdf4bbd604a0ce3898a48` |

Goldilocks `inv()` uses a fixed positive Fermat exponent, so zero maps to zero.
Existing zero/nonzero equality, inactive inverse, and generated differential
cases remain green without a test duplicating the witness implementation.
The fixed inversion removes the fast zero case by doing more work for zero;
this is a privacy hardening tradeoff, not a proving speedup.

Using the command prefix documented above, `execution::` passed 66 tests, and
`--test reaudit_private` passed its three ordinary tests with the timing
diagnostic ignored. Compiler output contained no warnings. Logs:
`/tmp/zheng-reaudit-hardened-execution.log` and
`/tmp/zheng-reaudit-hardened-regressions.log`.

The same ignored timing command used for the baseline produced the following
follow-up observations (`/tmp/zheng-reaudit-hardened-timing.log`):

| Sample | Secret | Total time for 100,000 witness generations |
|---|---:|---:|
| 0 | 0 | 47,657,500 ns |
| 1 | 11 | 46,683,584 ns |
| 2 | 11 | 46,870,792 ns |
| 3 | 0 | 47,192,125 ns |
| 4 | 0 | 46,646,583 ns |
| 5 | 11 | 46,871,250 ns |

The observed large difference disappeared for this probe. These measurements
establish neither constant time across all inputs nor a whole-runtime local
privacy guarantee. Activity branches, native execution, hidden table indexing,
field/runtime timing analysis, and the memory-erasure finding remain open with
the owner scopes described above. The native private specification now states
these limits explicitly.

The implementation and new regressions were committed as `deb5b8d` after root
review. The remaining local side-channel and erasure findings stay open.
