zheng (証 — proof/evidence in Japanese) implements constraints and proof protocols for [[nox]] and [[cyber]].

**Public execution binding is available through `zheng::execution::{prove_execution, verify_execution}` and the default `joy prove` / `joy verify` commands.** The verifier reconstructs constraints from the public program, authenticates the complete witness, and checks every constraint together with the public input, output and reduction count. This is a bounded, public certificate with linear verification and full witness disclosure: it is neither succinct nor zero knowledge. See [the execution contract](specs/execution.md) and [validation evidence](audit/public-execution.md).

The existing folded trace API (`commit` / `verify`) and standalone `zheng` CLI remain legacy statement checks: success does **not** authenticate execution or its public output. Their Brakedown/SuperSpartan machinery must not be used to infer the guarantees of the new execution API, or vice versa. Private execution and state proofs remain incomplete.

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
