# zheng

zheng (証 — proof, evidence) proves [[nox]] computations for [[cyber]]: hash-only, post-quantum zheng proofs over the Goldilocks field.

- one field: Goldilocks ([[nebu]]) for everything committed, its cubic extension Fp3 for every challenge
- one hash: [[hemera]] (Poseidon2 over Goldilocks), for Merkle trees and Fiat–Shamir, used as a random oracle
- one code: Reed–Solomon, opened by WHIR ([[lens]] `rspcs`) over hemera Merkle trees
- one IOP: Spartan over CCS with sumcheck; the nox machine (profiles 4–6) is a uniform AIR proved by a sumcheck zerocheck. no FRI, no univariate quotient
- one wire format: the `ZHENGPF1` envelope (magic, version, profile byte)

the design record is soft3 [[soft3/proposals/proof-system-repair|proposals/proof-system-repair.md]]. the bits each component claims, and whether they are proven or conjectured, are in the [soundness ledger](specs/soundness.md).

## status — master, 2026-10-27

master carries the repaired proof system: crate `zheng` 0.4.0, promoted from `release/0.4` on 2026-10-27. it is not on crates.io; crates.io's `zheng` 0.3.1 is the retired 0.3 fold, which was unsound.

| item | state on master |
|---|---|
| hemera | the crate pins `cyber-hemera` 0.3 (0.3.1: 4 + 4 full rounds, 16 partial rounds with the inverse S-box). the frozen material is hemera 0.4 (hemera#15: x⁷ in every round, 6 + 6 + 48 rounds). zheng moves to it in the draft sweep #69/#73, which waits on the owner's L3b decision (#78: keep the 64 KiB gate; #79: raise it to 72 KiB). every gadget, constraint count and number on this page is hemera 0.3.1 |
| statement binding | the verifier recompiles the relation from the program and pins `z[0] = 1`, inputs, outputs and cycles itself; verifying keys are derived by the verifier and absorbed into the transcript. attack fixtures (forged io, forged program, zeroed constant, meaningless witness) are in `rs/tests/attack_fixtures.rs` |
| challenges | Fp3 (`Transcript::squeeze_fp3`), about 192 bits |
| soundness ledger | `specs/soundness.md`. conjectured rows remain: the relation compiler (tested, not proven), the hash, program binding by digest, and IVC/wrap composition (recursive Fiat–Shamir). so the repair's release gate (no conjectured row) is not passed |
| accumulation, IVC, wrap | built: profiles 4, 5 and 6 |
| second verifier in Trident | not built (roadmap) |
| verify ≤ 1 ms | not met by any profile |
| legacy fold | the 0.3 folded trace API (`commit`, `open`, `verify`, `fold`, `decide`, the universal CCS, φ* SpMV, the Brakedown wire) compiles only with the cargo feature `legacy`. it is unsound (the fold is unchecked, the statement unbound, the constant wire free; see [decider](specs/decider.md)) and is deleted in phase 5. the `zheng` CLI drives only this path |

the phases, what is on master and what is in flight: [roadmap](roadmap/README.md).

## profiles

| profile | name | what the verifier checks | where |
|---|---|---|---|
| 0 | public certificate v3 | every row of the disclosed witness, exactly; soundness error 0 for the compiled relation; linear size | `execution::certificate` |
| 1 | succinct | Spartan over Fp3, then one WHIR opening of the committed witness | `execution::succinct` |
| 2 | zk | scheme 2 veil: masked Spartan and one hiding Reed–Solomon tensor opening, honest-verifier statistical zero knowledge; scheme 1: MPC-in-the-head, the linear-size fallback | `execution::veil`, `execution::zk` |
| 3 | state-public v3 | profile 0, plus every read authenticated under the statement's state root | `execution::state` |
| 4 | machine | the nox machine as one step relation, accumulated per segment and decided by one WHIR opening; the proof grows with the segments | `machine`, `accumulate` |
| 5 | recursive | IVC: each step's relation verifies the previous step; constant in the number of steps | `recursion::ivc` |
| 6 | wrapped | profile 5's final verifier, proved by three wrap levels; at most 64,213 B over every transcript | `recursion::wrap` |

measured on code revision a076137 (Apple M4 Max, 16 threads; sizes are deterministic, times are single-machine medians on a shared machine). the receipt, with load, commands and envelope hashes, is [audit/consistency-2026-10-27.md](audit/consistency-2026-10-27.md):

| profile | statement | envelope | prove | verify | command |
|---|---|---|---|---|---|
| 1 | hash.tri (2^10 variables) | 16,791 B | 39.6 ms CPU, 19.2 ms Metal | 4.9 ms | `fast_path` |
| 1 | Merkle membership, depth 16 (2^17) | 60,077 B | 660 ms CPU, 409 ms Metal | 173 ms | `fast_path` |
| 1 | Merkle membership, depth 32 (2^18) | 63,594 B | 1,347 ms CPU, 827 ms Metal | 324 ms | `fast_path` |
| 4 | hash.tri | 96,083 B | 7.4 s CPU | 5.0 ms | `envelope_profiles` |
| 5 | hash.tri | 407,947 B | 10.5 s CPU | 9.5 ms | `envelope_profiles` |
| 6 | hash.tri | 62,687 B | 66.8 s CPU (keys included), 12.1 GB peak | 5.4 ms | `envelope_profiles` |

profile 1 runs at ≥ 128 proven bits with grinding (106–112 without). profile 2 (veil) is not in these examples: its last measurement, 63.9 KB for the hash of a secret preimage, is in `audit/zk-profile-2026-10.md`.

the goal set by the owner on 2026-10-09: any nox computation in at most 64 KB, post-quantum, verified in at most 1 ms, constant in the number of steps. profile 6 meets the size and constancy goals, but no profile meets the 1 ms verify goal. user-device proving time per statement is in soft3 `audit/proof-latency-2026-10.md`. the older measurements are in [audit](audit/README.md).

## build

zheng builds against sibling checkouts through path dependencies (`../../<repo>` from `rs/` and `cli/`). master needs the hemera 0.3 revisions of its siblings, because the tips of nox `release/0.4` and lens `release/0.2` already require hemera 0.4. clone the stand side by side:

```
mkdir zheng-stand
cd zheng-stand
git clone https://github.com/cyberia-to/zheng
git clone https://github.com/cyberia-to/strata
git clone https://github.com/cyberia-to/hemera
git clone https://github.com/cyberia-to/nox
git clone https://github.com/cyberia-to/lens
git clone https://github.com/cyberia-to/tade
git clone https://github.com/cyberia-to/honeycrisp
git -C strata checkout 5ef0c84d155ef07f9a6f33ec0ee4db6b20896bc3
git -C hemera checkout fd55f99a17408c1f5a65d51c1ea73a6c60906f53
git -C nox checkout 12adaf886edc3f942d10b10a30b39b6d942405af
git -C lens checkout b1040c286912d6882f618a0490a09788cd30a542
git -C tade checkout 778dc6f7fa1bf1176d436a27686e8393c8f81db7
git -C honeycrisp checkout 595ce26265e52365b23a502c19215f6de8a11758
cd zheng
```

| sibling | revision | what it is |
|---|---|---|
| strata | 5ef0c84 (`main`) | `strata-nebu` 0.1.1, the field |
| hemera | fd55f99 (`main`) | `cyber-hemera` 0.3.1 |
| nox | 12adaf8 (`release/0.4`, before nox#31 moved it to hemera 0.4) | `cyber-nox` 0.3.0 |
| lens | b1040c2 (`release/0.2`, before lens#37 moved it to hemera 0.4) | `cyber-lens` 0.2.0, `cyber-lens-gpu` 0.1.1 |
| tade | 778dc6f (`main`) | `tade` 0.1.0, the CLI's chunk stream |
| honeycrisp | 595ce26 (`main`) | `aruminium`, Metal for lens's GPU backend |

then, from `zheng/`:

```
cargo build --release --locked
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets --features zheng/legacy,zheng/serde,zheng/test-hooks,zheng-cli/legacy -- -D warnings
cargo run --release --locked -p zheng --example fast_path -- hash.tri merkle-16 merkle-32
ZHENG_PROFILES=1,4,5,6 cargo run --release --locked -p zheng --example envelope_profiles -- hash.tri
```

`fast_path` proves profile 1 on the backend named by `ZHENG_BACKEND` (`cpu` is the default; `metal` or `webgpu` produce the same bytes). `envelope_profiles` proves one fixture under profiles 1, 4, 5 and 6; `ZHENG_ENVELOPE_DIR=<dir>` writes the envelopes. the test suite takes about 9 minutes on an M4 Max (the dev profile is built at opt-level 3).

## layout

```
rs/        the library, package `zheng`
cli/       the `zheng` binary, legacy API only: cargo run -p zheng-cli --features legacy -- help
specs/     the contracts: profiles, envelope, soundness ledger, machine, recursion
docs/      explanations
roadmap/   the repair's phases and the work in flight
audit/     measurements and adversarial reviews, dated
```

## dependency graph

```
strata/nebu (field)
  ↓
hemera (hash) ──→ lens (WHIR, TensorRs; GPU backends through honeycrisp)
  ↓                 ↓
nox (programs, reduction) ──→ zheng (proofs) ← this repo
                                ↓
                  joy · bbg · foculus · mudra → soft3
```

the reasoning behind each choice is in [docs/explanation](docs/explanation/README.md).
