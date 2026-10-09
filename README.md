zheng (証 — proof/evidence in Japanese) implements constraints and proof protocols for [[nox]] and [[cyber]].

Public execution binding is available through `zheng::execution::{certify_execution, verify_certificate}` (profile v3) and the default `joy prove` / `joy verify` commands. The verifier reconstructs constraints from the public program, places the constant, public input, output and reduction count itself, fills the remaining witness positions from the certificate and checks every constraint exactly. Authenticated-state execution has the same profile (`execution::state::certify_state_execution`). These bounded public certificates have linear verification and disclose the witness. Every proof travels in one envelope, `zheng::envelope` (magic `ZHENGPF1`, version, profile byte). See [the execution contract](specs/execution.md), [the soundness ledger](specs/soundness.md) and [historical public validation](audit/public-execution.md).

Native private proofs are available through `zheng::execution::zk::{prove, verify}`. Secret call/divine inputs and queries over authenticated public state use the existing nox relation with a three-party arithmetic MPC-in-the-head proof over Goldilocks and Hemera. Joy uses this backend for secret inputs and `--zk`; Trisha owns the separate Triton/Neptune stack. The native protocol fixes 219 repetitions, has linear proof size and verification cost, and relies on the stated Fiat–Shamir/random-oracle and Hemera assumptions. See [native private CCS](specs/native-private-ccs.md) and [execution/state integration](specs/ccs-execution-backends.md) for precise bounds and disclosure. Independent production-security review remains outstanding.

The folded trace API (`commit`, `open`, `verify_eval`, `verify`, `fold`, `decide`), the universal CCS, HyperNova folding, φ* SpMV (`rs/src/phi/`) and the standalone `zheng` CLI compile only with the cargo feature `legacy`, off by default. That path is unsound — the fold is unchecked and the statement is unbound ([decider](specs/decider.md) §soundness) — and must not be used for production; it stays for one release so external consumers can migrate.

The sumcheck and Spartan IOP are generic over the challenge field (`zheng::field::ChallengeField`: Goldilocks or its cubic extension Fp3); `Transcript::squeeze_fp3` draws Fp3 challenges.

```
COMPONENT         │ ROLE                           │ INSTANCE
──────────────────┼────────────────────────────────┼─────────────────────
hash              │ Fiat-Shamir, Merkle trees      │ hemera 
field             │ arithmetic substrate           │ nebu
VM                │ execution trace generation     │ nox
IOP               │ constraint verification        │ superspartan
core protocol     │ exponential sum → log rounds   │ sumcheck
PCS               │ polynomial commitment          │ none in profile v3; Brakedown (legacy)
private protocol  │ hidden CCS witness             │ arithmetic MPC-in-head
```

## dependency graph

```
nebu (field)
  ↓
hemera (hash)
  ↓
zheng (proofs) ← this repo
  ↓
bbg (state)
```

## layout

```
rs/    the library crate (package `zheng`)
cli/   the `zheng` binary — command-line face (see specs/cli.md)
```

build the workspace with `cargo build`; the CLI drives only the legacy API: `cargo run -p zheng-cli --features legacy -- <command>`.

```
zheng demo hash    legacy hash trace statement demo
zheng eval         commit / open / verify a polynomial (Brakedown PCS)
zheng run -e '…'   legacy trace statement check for a nox formula
zheng pack / prove program capsule → legacy trace statement
```

the CLI emits a [[tape]] chunk stream on stdout (with a human summary on stderr).

see [[stark]] for the general theory, [[cyber/proofs]] for the full proof taxonomy
