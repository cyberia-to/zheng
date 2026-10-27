# trace to proof

the concrete journey from a [[nox]] execution to a [[zheng]] proof. there are two paths: one statement is compiled into one relation; a run of any length is a trace of the nox machine. both end in sumchecks and one Reed–Solomon opening per committed object; neither uses a quotient polynomial or FRI.

## 1. one statement: the compiled relation (profiles 0–3)

the relation compiler turns the nox program and the shape of its subject into one [[CCS]]: every operand, intermediate value and output is a wire; field operations, conditionals, word operations and [[hemera]] rounds are rows, of degree 1 to 7. the verifier compiles the same CCS from the same program and places `z[0] = 1`, the inputs, the outputs and the cost itself, so a proof can only fill the free witness positions.

```
nox program + statement (io, cycles)
    → relation compiler → CCS (verifier and prover alike)
    → prover fills the witness w
    → public profile (0, 3): disclose w; the verifier checks every row exactly
    → succinct profile (1): commit w̃ (Reed–Solomon + hemera Merkle root)
        → Spartan over Fp3 (outer + inner sumcheck) → point r
        → one WHIR opening of w̃(r)
    → zk profile "veil" (2): masked sumchecks + one hiding RS tensor opening
```

one hemera hash of a digest costs about 2,700 constrained wires, because nox hashes nouns structurally (every atom decomposed into 64 bits); one relation is capped at `2^20` rows. `hash.tri` gives a 6,463 B public certificate and a 16,756 B succinct proof (`audit/succinct-profile-2026-10.md`; soft3 `audit/proof-latency-2026-10.md`).

## 2. a run of any length: the machine trace (profiles 4–6)

`nox::reduce` on any program becomes a trace of one fixed row relation ([[zheng/specs/machine|machine]]): 64 phase-1 columns, 15 phase-2 columns, 2 challenges, degree 8, 604 constraints, the same for every program and input — so the verifier's key does not depend on the program.

```
[0, P)            INIT    one init entry per row: the program and subject DAG
[P, P + M)        machine one row per continuation-machine step, the last one TERM
[P + M, start)    PAD
[start, N)        PERM    32-row blocks: one hemera permutation each
```

- memory is write-once: atoms, pairs, continuation frames, digests and state reads are tuples checked by a logUp argument over Fp3, so every read equals a written value.
- each evaluation row carries one of sixteen opcode flags and adds nox's cost for that opcode, so the statement's cycle count is enforced row by row.
- the statement enters through public columns the verifier evaluates itself: the init region, the phases of the permutation blocks, hemera's round constants, the output digest and `cycles`.
- the PERM blocks are hemera 0.3.1's permutation (4 + 4 full rounds, 16 partial rounds), the version the crate pins; the frozen hemera 0.4 re-cuts the block in the draft sweep zheng#69/#73.

the trace is cut into segments of `2^14` rows. each segment is committed as Reed–Solomon codewords under hemera Merkle trees and proved by a sumcheck zerocheck over its rows plus a successor (shift) argument linking consecutive rows; what is left are evaluation claims on the committed words. those claims are accumulated (profile 4), checked inside the next step (IVC, profile 5), and wrapped to at most 64,213 B (profile 6) — see [[zheng/docs/explanation/recursion|recursion]].

## multilinear encoding

both paths commit tables the same way. a table of `2^n` rows and `2^m` columns is one multilinear polynomial in `n + m` boolean variables: the first `n` address the row, the last `m` the column, and the polynomial is the unique multilinear extension that agrees with the table on every binary input. padding to a power of two lets the [[sumcheck protocol]] range over the full hypercube `{0,1}^{n+m}`. a constraint that must hold on every row becomes a claim that a polynomial vanishes on the hypercube; a random `eq` weight turns it into a sum, and sumcheck reduces the sum to one evaluation at a random point of Fp3, which the commitment opens.

## the retired register trace

the 0.3 design proved a fixed 16-register trace (one row per reduction, one column per register, a selector over 18 pattern constraints) by folding it into an accumulator and opening it with an expander-code commitment. the fold was never checked, the statement was unbound and the commitment had no real opening ([[zheng/docs/explanation/recursive-brakedown|recursive-brakedown]]). that code survives only behind the cargo feature `legacy` (unsound, off by default) until phase 5 deletes it.

## references

- see [[whirlaway]] for the architecture of the succinct profile
- see [[superspartan]] for the IOP that verifies a compiled relation
- see [[nox]] for the VM specification and pattern definitions
- see [[hemera]] for the Poseidon2 hash used in the relation and in every Merkle commitment
