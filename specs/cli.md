---
tags: zheng, cli, reference
crystal-type: entity
crystal-domain: computer science
alias: zheng CLI, zheng command
---
# cli

the `zheng` command-line face of the proof system. drives the library's five
entry points from a shell and emits results as a [[tape]] chunk stream.

## invocation

```
zheng <command> [args]
```

output convention:
- **stdout** — a [[tape]] chunk stream (TAPE — Typed Annotated Payload Exchange).
  every run ends with a `render::STATUS` chunk carrying the process exit code.
  this is the machine / cyb-terminal channel.
- **stderr** — a human-readable summary of the same result.
- **exit code** — `0` proof verified, `1` prover/verifier error, `2` usage error.

nothing is written to stdout except tape frames, so `zheng ... | <tape reader>`
is always well-formed.

## commands

### run — prove a formula end to end

```
zheng run -e '<formula>' [--object N] [--budget B]
```

evaluates a nox formula, proves the resulting execution trace, and verifies the
proof — one process, no intermediate files.

- `-e '<formula>'` — a nox data formula in bracket syntax (`[a b c]` → right-nested
  pairs, atoms are u64 decimals). same grammar as the `nox` CLI. required.
- `--object N` — the object noun the formula runs against (atom `N`). default `0`.
- `--budget B` — focus budget for reduction. default `1_000_000`.

emits a `render::STRUCT` report chunk (see **report** below) and a status chunk.

aux-free patterns (arithmetic, bitwise, trivial) prove with no auxiliary data.
formulas whose trace needs opening proofs (hash pattern 15, axis pattern 0, look
pattern 17) require auxiliary data the general path does not yet derive; `run`
reports a prover error for those. `demo hash` exercises the hash pattern with
correctly derived auxiliary data.

### demo — run a built-in program

```
zheng demo hash
```

runs a known-good program that exercises a specific pattern with correct
auxiliary data, then proves and verifies it. `hash` proves `[15 [1 s]]` with the
`HashAux` rate derived from the subject's structural digest.

### eval — polynomial commitment demo

```
zheng eval
```

commits a small multilinear polynomial, opens it at a point, and verifies the
opening via `zheng::open` / `zheng::verify_eval`. reports the point, claimed
value, and verify result.

### pack — serialize a program capsule

```
zheng pack -e '<formula>' [--object N] [--budget B] -o <file>
```

writes the program (formula text, object, budget) to `<file>` as a single
[[tape]] chunk (see **program file format**). does not evaluate or prove.

a nox execution trace cannot round-trip on its own — `TraceRow` columns are
crate-private, so a trace has no public reconstruction path. the program is the
canonical serializable unit: re-executing it deterministically reproduces the
exact trace, so the capsule stores the program and `prove` re-runs it.

### prove — prove a program capsule

```
zheng prove <file>
```

reads a program-capsule [[tape]] file, re-executes it to reproduce the trace,
proves (aux-free), verifies, and reports. a tampered capsule reduces to a
different trace (or fails to parse) — reported as an error, not a false pass.

### help

```
zheng help    |    zheng -h    |    zheng --help
```

## report (STRUCT chunk)

honest, cheaply-measurable proof statistics as nested `kv` pairs:

| key | meaning |
|---|---|
| `trace_rows` | number of trace rows proved |
| `groups` | CCS-structure groups (one accumulator each) |
| `steps` | total folded steps across all groups |
| `outer_rounds` / `inner_rounds` | sumcheck round counts (first group) |
| `verify` | `ok` or `fail` |
| `commit_ms` / `verify_ms` | wall-clock timings |

proof size in bytes is **not** reported: `Proof::pcs_opening` (a lens `Opening`)
has no canonical byte encoding yet. structural counts are reported instead. a
`.proof` file format is reserved for the proof-serialization milestone.

## program file format

a single [[tape]] chunk, `(sigil::BAR, render::STRUCT)` (code-with-data), whose
payload is `encode_nested` of three `kv` pairs:

```
kv "formula" → text     the bracket-syntax formula
kv "object"  → text     object atom, decimal
kv "budget"  → text     focus budget, decimal
```

canonical: the `kv` order is fixed (formula, object, budget) and tape's varint
framing is deterministic, so one program encodes to one byte sequence.

## deferred

- offline proof serialization (`.proof` file, standalone `verify <file>`) — needs
  a canonical codec for `Proof` including the lens `Opening` (cross-repo).
- raw-trace serialization — blocked on a public `TraceRow` constructor in nox.
- general auxiliary-data derivation for hash / axis / look formulas under `run`.
- rich `render::TABLE` output (current report uses `render::STRUCT` kv pairs).
