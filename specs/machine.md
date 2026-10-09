---
tags: zheng, nox, machine, air, step relation, spec
crystal-type: entity
crystal-domain: comp
alias: nox machine, uniform step relation
---
# the nox machine — one step relation for nox runs of any length

`rs/src/machine/` (relation), `rs/src/air/` (protocol). Phase 3 of the
proof-system repair (soft3 `proposals/proof-system-repair.md` §3,
"unbounded programs"); the requirements it answers are
`audit/general-nox-relation-review.md` § "complete computed-formula
support".

## statement

`MachineStatement { program, input, output, cycles, budget }`: program
and output are nouns in prefix tokens, `input` public atoms, the subject
`[x_k [… [x_1 0]]]` (joy's convention: last input at the head). It claims
that `nox::reduce(subject, program, budget)` (no jets) returns `Ok` with
exactly that output noun after exactly `cycles` of nox's cost. The
verifier derives everything else.

## verifier key

The row relation (64 phase-1 columns, 15 phase-2 columns, 2 challenges,
degree 8, `Machine::shape`) is the same for every program and input. A
statement enters through public columns the verifier evaluates itself and
five constants:

| public column | rows | value |
|---|---|---|
| init region, tag, key, p0, p1 | `[0, P)` | the init entries (`Prefix`) |
| first machine row | `P` | 1 |
| first row | 0 | 1 (running-sum pin) |
| region | `≥ start` | 1 (`Region`, period 32) |
| phases: bits0, bits1, mds, full, partial, out, continue | `≥ start` | per phase of the 32-row block |
| round constants `rc_0..rc_15` | `≥ start` | hemera's, per round phase |

constants: `fml0`, `obj0` (ids of the program and the subject in the init
DAG), `P`, the output digest, `cycles`. Geometry (`log_rows`, `start`, the
segment count) is chosen by the prover and checked by the verifier
(`start` a multiple of 32, `P < start`, at least one block of region).

## trace

```text
[0, P)            INIT    one init entry per row: the program and subject DAG
[P, P + M)        machine one row per step, the last one TERM
[P + M, start)    PAD
[start, N)        PERM    32-row blocks: one hemera permutation each
```

The init DAG is canonical: post-order over program then subject,
structurally equal nouns share one id, ids `1..=P`.

### memory

A write-once table of tuples `(tag, key, p0, p1, p2, p3)` (`layout.rs`):
`ATOM(id; v)`, `PAIR(id; l, r)`, continuation frames `CONS1, CONS2,
COMP1, COMP2, BR, B1·, B2·, UHASH, UINV` keyed by a fresh id, `DIG(id;
d0..d3)` (structural digest), `HOP(id; h0..h3)` (the hash opcode's
output), `ABASE(id; …)` (an atom's sponge digest). Every row has four
slots; a slot's tag and read/write mode are polynomials in the row's own
kind and flags (`slots.rs`) — never chosen freely. Noun and frame ids
come from the `ALLOC` counter (strictly increasing, unique); `DIG`, `HOP`
and `ABASE` are written only by permutation blocks that recompute them,
so every such write is correct (by induction over the acyclic noun DAG)
and duplicates are harmless.

**logUp** (phase 2, challenges `α, β ∈ K`): slot `s` has the committed
inverse `h_s = 1/(α − enc_s)`, `enc = tag + β·key + β²·p0 + … + β⁵·p3`;
the cyclic running sum `S' = S + Σ_s (read_s − write_s·M_s)·h_s` starts at
zero on row 0 and closes at zero; `M_s` (free on writes) counts the
reads. This is `Σ_reads 1/(α−e) = Σ_writes M/(α−e)`: every read tuple
equals a written one (Haböck, eprint 2022/1530, Lemma 5 — logarithmic
derivatives — with `char K > #reads`; fingerprint collisions by
Schwartz–Zippel in `β`, degree 5).

### transitions

State `(OBJ, X, K, D, CYC, ALLOC)`: subject, formula / value, the top
frame id (0 = empty), depth, cycles, next id.

- **EVAL** `(obj, fml, K, d)`: read `PAIR(fml) = (tid, body)`,
  `ATOM(tid) = t`; one opcode flag with nox tag `t` (axis, quote,
  compose, cons, branch, add, sub, mul, inv, eq, hash); `(d − 1001)` has an
  inverse (nox's `MAX_DEPTH`: depth only grows by one, so it never passes
  1000); `CYC += COSTS[t]`. Binary opcodes read `PAIR(body) = (a, b)`,
  push the frame `(b, obj, d, K)` and evaluate `a` at `d + 1`; unary
  (hash, inv) push `(0, 0, 0, K)` and evaluate `body`; quote returns
  `body`; axis reads `ATOM(body) = a`: `a = 1` returns `obj`, `a = 0`
  reads `DIG(obj)` and builds `hash_data`, `a ≥ 2` navigates.
- **RET** `(val, K)`: `K = 0` is TERM (reads `DIG(val)` = the statement's
  output digest, `CYC = cycles`, no machine row follows); otherwise read
  the frame `K` under the tag of the row's frame flag and:
  `CONS1/COMP1/B1·` push the successor frame and evaluate the second
  child; `CONS2` writes `PAIR(new; x, val)`; `COMP2` evaluates the
  computed formula `val` on the computed subject `x`; `BR` reads
  `ATOM(val) = tv` (0 selects yes) and `PAIR(rest)`; `B2 add/sub/mul`
  read two atoms and write the result atom; `B2 eq` reads both operands
  (atoms: compare values; atom vs pair: unequal; pair vs pair: an `EQD`
  row compares `DIG`s limb by limb); `UHASH` reads `HOP(val)` and builds
  `hash_data`; `UINV` writes `y` with `y·u = 1`.
- **AX1** peels the address `a = 2a' + b` into the reversed path
  `R' = 2R + b` until `a' = 1`; **AX2** walks `R = 2R' + c`, reading
  `PAIR(node)` and taking `c ? r : l`, until `R' = 1`. Each phase allows at
  most 31 rows (a counter with an inverse of `cnt − 31`): with
  `2^n + Σ b_k 2^k ≡ a (mod p)` and `n ≤ 31` both sides are below
  `2^32 < p`, so the bits are `a`'s binary digits. Addresses `≥ 2^32`
  are refused (a completeness gap, never a soundness one).
- **HDA / HDB**: `hash_data(h)` = four atoms then three pairs, ids
  `ALLOC..ALLOC+6`.

Sequencing: machine rows chain until TERM; TERM and PAD rows are never
followed by machine rows; the INIT region and the PERM region are forced
by public columns; the first machine row is pinned to `EVAL(fml0, obj0,
K = 0, d = 0, cyc = 0, alloc = P+1)`. Hence the machine rows are exactly
one run from the pinned start to a TERM.

### permutation region

A block is 32 rows: phases 0–1 decompose an atom into 64 boolean bits
and check it is canonical (`< p`), phase 2 holds the job's input and
applies hemera's initial linear layer, phases 3–26 are the 24 rounds (4
full with `x^7`, 16 partial with `x^{-1}` on lane 0 (`0 ↦ 0`), 4 full; the
state before each round on the round's row, round constants as public
columns), phase 27 writes the first four lanes under the job id, 28–31
idle. Jobs: `PAIR` (node over the children's `DIG`s, flag 2),
`ATOM1` (the leaf sponge over `v`'s eight bytes, seven per element, pad
`0x01`, length 8 in capacity lane 10), `ATOM2` (chunk node, flag 4) and
`HOP` (plain permutation of `[d, 0…]`). `machine::hemera` reads every
matrix and constant from hemera; tests check the row function against
`hemera::permutation::permute` and the digests against
`nox::data::hash_{atom,pair}`.

## segments

A run longer than `2^n` rows (default `2^14`) is cut into segments.
All phase-1 words are committed (each answering `fresh_ood` out-of-domain
samples right after its root, binding it to one codeword of its list),
then the shared challenges, then all phase-2 words (bound the same way). Within a segment the successor is non-cyclic; the last
row's next is the next segment's first row (cyclically, segment 0 after
the last), sent in the clear and tied to that segment's words by a row-0
claim each. The running sum carries across segments and closes once.

## proving (`air`)

Per segment: zerocheck over the row variables
`Σ_x eq(τ,x)·Σ_k μ^k C_k(W(x), W(x+1), P(x)) = 0` (degree 9), the prover
sends every column at `ρ` and at the successor; one product sumcheck
with `eq(ρ,·) + β·nxt(ρ,·)` reduces both column sets of both words to one
point. Each word carries two claims (its own, the previous segment's
boundary); one accumulation step per segment folds its two words into the
accumulator; one decider. The verifier evaluates the constraints once per
segment (`O(constraints)`), the public columns (`O(P + log N)`), the
successor polynomial (`O(log N)`).

## coverage and deviations from native nox

- covered: opcodes 0–9 except lt, and 15, with computed formulas;
- refused (no trace exists): lt (10), xor/and/not/shl (11–14), call (16),
  look (17), axis addresses `≥ 2^32`;
- `eq`: two atoms are compared by value and an atom differs from a pair —
  equal to nox's digest comparison unless hemera collides (nox's identity
  already assumes it does not);
- the arena capacity of `nox::Reduction<N>` is not modelled (the relation
  proves the result of an unbounded arena);
- budget: native nox gives each child of a binary opcode its static
  `bound()` as budget when both bounds fit; "the run succeeds iff
  `cycles ≤ budget`" therefore relies on `bound()` being an upper bound
  of the actual cost (checked for the covered opcodes by review, and by
  the exact-budget tests: `cycles` passes, `cycles − 1` fails).

## soundness status

The relation is tested, not proven: twenty single-opcode programs, joy's
compiled `hash.tri` / `add.tri`, an eleven-hash chain, Merkle paths and
long addition trees agree with `nox::reduce` on output and cycles; every
native failure class is a machine failure; tampered traces violate it.
`specs/soundness.md` carries it as a tested row.
