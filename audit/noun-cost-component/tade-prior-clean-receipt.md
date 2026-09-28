# Native private CCS acceptance

Date: 2026-09-27. This receipt covers Zheng's native private proof backend and
isolated CLI installation. It is feature-branch evidence, not a release candidate.
Joy consumer acceptance is recorded separately in `joy/audit/native-private/`.

## Source inputs

| Input | Committed revision |
|---|---|
| Native backend and contracts | `6b5a8a85535efb8d2852736af738278a9bd92db7` |
| CLI help guarantee correction | `50bbacd9837896e030b0c6649387d651de23c529` |
| Accepted release base | `80a8ca90208c3b49c4f2a8507d75fd17785fdfe3` |
| nox | `c9f7486a74fe81bfc194b598da40f6343ecb2ef1` |
| hemera | `a931a0a8e7ed369852ce0f8bc6451a59745ee692` |
| lens | `17cafe91431977b738e5b72361187cd01ad93638` |
| strata | `d2eb1763b8caf04e6c7647ac6fe99761519c2ef9` |
| tade, CLI transport only | `c1d81c75725df0a666c36d81ef33c3a60eb007f3` |

Every input above was clean when checked with `git status --porcelain`; revisions
were read with `git rev-parse HEAD`. Sibling paths resolve to isolated worktrees.
`cargo metadata --format-version 1 --all-features --locked --offline` at the
final source revision reports no Trisha, Triton, TASM, Neptune, `twenty-first`
or `bfieldcodec_derive` dependency. The new
direct utility dependencies are `getrandom` and `zeroize`, locked respectively
to `0.3.4` and `1.9.0`. `shasum -a 256 Cargo.lock` at both source revisions gives
`26168c02c3fe288833db961e832a4b80d3a84c71c73015391f87a25329e79163`.

Environment observed with `uname -m`, `sw_vers -productVersion`,
`rustc --version` and `cargo --version`: macOS arm64 26.4.1,
rustc 1.95.0 (`59807616e`, Homebrew), Cargo 1.95.0 (`f2d3ce0bd`, Homebrew).
These are local CPU results; this receipt contains no cross-platform execution
or hardware acceleration measurement.

## Validation

Commands below run from
`/Users/master/cyber/.worktrees/selfhost-0.4-native-private/zheng`.
The full check and acceptance suite were launched from clean source
`6b5a8a85535efb8d2852736af738278a9bd92db7`:

```sh
CARGO_TARGET_DIR=../target-zheng-check cargo check --workspace --all-targets --all-features --locked --offline
CARGO_TARGET_DIR=../target-zheng-release cargo test --workspace --all-features --release --locked --offline
```

Check passed with zero Rust warnings. The full suite passed 219 tests: 212 library
tests, five execution-adversarial integration tests and two CLI tests, with zero
failures or ignored tests. Both existing exhaustive legacy proof-wire mutation
tests completed successfully. Local logs:
`/tmp/zheng-native-private-6b5a8a8-check.log` and
`/tmp/zheng-native-private-6b5a8a8-tests.log`.

The full suite includes eight new native backend tests. Their coverage is:

- Exact relation, statement and public-coordinate binding; fresh proof randomness.
- Invalid witnesses forged through an internal path that bypasses honest-prover
  validation, including the all-zero witness and mandatory constant coordinate.
- All three opening orientations and reconstruction of the corresponding views.
- Altered seeds, fields, commitments, dimensions, challenge values, truncated and
  trailing data, noncanonical fields and spliced repetitions.
- Linear and higher-degree CCS, and bounds checked before proof allocation.
- Bounded serde admission, including oversized and admitted-but-truncated hints.
- Exhaustive small-field comparison of the real two-view distribution against a
  witness-free simulator for two distinct square-root witnesses.

After the CLI-only correction at `50bbacd9837896e030b0c6649387d651de23c529`:

```sh
CARGO_TARGET_DIR=../target-zheng cargo check -p zheng-cli --all-targets --locked --offline
CARGO_TARGET_DIR=../target-zheng cargo test -p zheng-cli --locked --offline
```

The check had zero Rust warnings; both CLI tests passed. Logs:
`/tmp/zheng-native-private-banner-check.log` and
`/tmp/zheng-native-private-banner-tests.log`. The native backend source is
unchanged by this correction.

## Committed CLI installation

Both committed source revisions were installed with the following command;
the final installation uses `50bbacd9837896e030b0c6649387d651de23c529`:

```sh
CARGO_TARGET_DIR=../target-zheng cargo install --path cli --locked --offline --root ../install-zheng-committed
../install-zheng-committed/bin/zheng --help
shasum -a 256 ../install-zheng-committed/bin/zheng
stat -f '%z' ../install-zheng-committed/bin/zheng
```

The final help command exited zero, displayed the native soft3 identity and
marked the legacy CLI statement commands explicitly. The former blanket
post-quantum and sub-millisecond claims are absent. Installed binary size:
781,440 bytes. SHA256:
`6a23492e9e62c800892b619ed44ca717938f896aa0f4a08af45e82862d455d5a`.
Installation produced no Rust warnings; Cargo's isolated-prefix PATH reminder
is an installation advisory. Logs and captured help:
`/tmp/zheng-native-private-50bbacd-install.log`,
`/tmp/zheng-native-private-50bbacd-help.stdout` and
`/tmp/zheng-native-private-50bbacd-help.stderr`.

This CLI help smoke verifies installation and presentation. Native private
proving is exercised by the library tests and Joy's consumer validation.

## Assurance and limits

The implemented protocol is [native private CCS](../../specs/native-private-ccs.md),
with exactly 219 repetitions. Its interactive error bound is `(2/3)^219 < 2^-128`.
Noninteractive security additionally depends on Fiat–Shamir in the random-oracle
model and the stated Hemera assumptions. Internal source review checked the
arithmetic decomposition, transcript binding, wire admission and privacy model;
this is not an independent production cryptographic audit.

Proof size and verifier work scale linearly with the admitted circuit, multiplied
by the fixed repetition count. The 256 MiB native payload cap and circuit work
bounds are executable admission limits, not benchmark throughput claims.
Public program, input/output, circuit shape and reduction count remain visible.
Hidden queries operate over authenticated public BBG tables. The inherited nox
relation supports bounded static continuations and fixed branch output shapes.
This receipt makes no succinctness, recursion, complete dynamic-VM coverage or
128-bit post-quantum claim. Owned view and seed buffers are cleared; caller-owned
witness memory and all possible transient copies are outside that guarantee.

## Delivery boundary

`git ls-remote --symref origin HEAD refs/heads/release/0.4` initially reported
default `master` at `44bd5bfec5cb6764123ea513a33a26c0877a488c` and no release branch.
`release/0.4` was then created with a non-force push at accepted
`80a8ca90208c3b49c4f2a8507d75fd17785fdfe3`. A subsequent remote inspection confirmed
that base and the unchanged default revision. Feature work belongs to
`feat/0.4-native-private-proofs`. No default-branch merge, tag, release publication
or package publication was performed by this delivery.
