the proof system for [[cyber]]. implements the Whirlaway architecture: [[SuperSpartan]] IOP + Brakedown PCS + [[sumcheck]] protocol. zero trusted setup. post-quantum. sub-millisecond verification.

zheng (証 — proof/evidence in Japanese) provides the cryptographic machinery that turns [[nox]] execution traces into compact, verifiable proofs. one commitment, one opening, one proof.

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
zheng demo hash    prove + verify a Poseidon2 hash program
zheng eval         commit / open / verify a polynomial (Brakedown PCS)
zheng run -e '…'   prove + verify a nox formula
zheng pack / prove program capsule → proof
```

the CLI emits a [[tape]] chunk stream on stdout (with a human summary on stderr).

see [[stark]] for the general theory, [[cyber/proofs]] for the full proof taxonomy
