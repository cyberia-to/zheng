zheng (証 — proof/evidence in Japanese) implements constraints and proof protocols for [[nox]] and [[cyber]].

Public execution binding is available through `zheng::execution::{prove_execution, verify_execution}` and the default `joy prove` / `joy verify` commands. The verifier reconstructs constraints from the public program, authenticates the complete witness, and checks every constraint together with public input, output and reduction count. These bounded public certificates have linear verification and disclose the witness. See [the execution contract](specs/execution.md) and [historical public validation](audit/public-execution.md).

Native private proofs are available through `zheng::execution::zk::{prove, verify}`. Secret call/divine inputs and queries over authenticated public state use the existing nox relation with a three-party arithmetic MPC-in-the-head proof over Goldilocks and Hemera. Joy uses this backend for secret inputs and `--zk`; Trisha owns the separate Triton/Neptune stack. The native protocol fixes 219 repetitions, has linear proof size and verification cost, and relies on the stated Fiat–Shamir/random-oracle and Hemera assumptions. See [native private CCS](specs/native-private-ccs.md) and [execution/state integration](specs/ccs-execution-backends.md) for precise bounds and disclosure. Independent production-security review remains outstanding.

The existing folded trace API (`commit` / `verify`) and standalone `zheng` CLI remain legacy statement checks. Execution and public-output authentication belong to the separate execution APIs above. Brakedown/SuperSpartan, the public full-witness certificate and native private proofs each have their own protocol contract.

**φ* SpMV** (`rs/src/phi/`): multi-row CCS for sparse matvec + tri-kernel `prove_phi_star` / `verify_phi_star` — the domain-local core of provable consensus (see `specs/phi-spmv.md`).

```
COMPONENT         │ ROLE                           │ INSTANCE
──────────────────┼────────────────────────────────┼─────────────────────
hash              │ Fiat-Shamir, Merkle trees      │ hemera 
field             │ arithmetic substrate           │ nebu
VM                │ execution trace generation     │ nox
IOP               │ constraint verification        │ superspartan
core protocol     │ exponential sum → log rounds   │ sumcheck
PCS               │ polynomial commitment          │ Brakedown
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

build the workspace with `cargo build`; run the CLI with `cargo run -p zheng-cli -- <command>`.

```
zheng demo hash    legacy hash trace statement demo
zheng eval         commit / open / verify a polynomial (Brakedown PCS)
zheng run -e '…'   legacy trace statement check for a nox formula
zheng pack / prove program capsule → legacy trace statement
```

the CLI emits a [[tape]] chunk stream on stdout (with a human summary on stderr).

see [[stark]] for the general theory, [[cyber/proofs]] for the full proof taxonomy
