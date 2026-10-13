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

`MachineStatement { program, input, output, cycles, budget, state }`:
program and output are nouns in prefix tokens, `input` public atoms, the
subject `[x_k [… [x_1 0]]]` (joy's convention: last input at the head).
It claims that `nox::reduce(subject, program, budget)` (no jets) returns
`Ok` with exactly that output noun after exactly `cycles` of nox's cost,
for some call witnesses, with every `look` answered from `state`. The
verifier derives everything else.

`state = Some(MachineState { root, reads })`: the four-limb root the run
reads under and every read `(namespace, key, value)` once (namespace ≤ 9,
at most 4096 reads). The verifier takes `StateEvidence`
(`execution::state_evidence`, the BBG layout of state v3), authenticates
it under `root` and checks each read against the authenticated table
before the reads enter the init region — as state v3 does, no caller
authenticates anything (`machine::verify_with_state`; the envelope passes
its evidence).

## verifier key

The row relation (64 phase-1 columns, 15 phase-2 columns, 2 challenges,
degree 8, 604 constraints, `Machine::shape`) is the same for every program
and input. A statement enters through public columns the verifier
evaluates itself and six constants:

| public column | rows | value |
|---|---|---|
| init region, tag, key, p0, p1, p2 | `[0, P)` | the init entries (`Prefix`) |
| first machine row | `P` | 1 |
| first row | 0 | 1 (running-sum pin) |
| region | `≥ start` | 1 (`Region`, period 32) |
| phases: bits0, bits1, mds, full, partial, out, continue | `≥ start` | per phase of the 32-row block |
| round constants `rc_0..rc_15` | `≥ start` | hemera's, per round phase |

constants: `fml0`, `obj0` (ids of the program and the subject in the init
DAG), `P`, the output digest, `cycles`, the digest of the root noun
`[r0 [r1 [r2 r3]]]` (zero without state). Geometry (`log_rows`, `start`, the
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
structurally equal nouns share one id; then one `STATE` entry per read;
ids `1..=P`.

### memory

A write-once table of tuples `(tag, key, p0, p1, p2, p3)` (`layout.rs`):
`ATOM(id; v)`, `PAIR(id; l, r)`, continuation frames `CONS1, CONS2,
COMP1, COMP2, BR, UHASH, UINV, CALL1, CALL2` and `B1(op)`, `B2(op)`
(tags `64 + op`, `96 + op`, op the nox tag) keyed by a fresh id, `DIG(id;
d0..d3)` (structural digest), `HOP(id; h0..h3)` (the hash opcode's
output), `ABASE(id; …)` (an atom's sponge digest), `STATE(id; ns, key,
value)` (init only, verifier-authenticated) and `CELL(id; top, next)`
(the call-witness stack). Every row has four
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
  `ATOM(tid) = t`; one of 16 opcode flags: axis, quote, compose, cons,
  branch, add, sub, mul, inv, eq, hash, lt, not, call, look with nox tag
  `t`, and `WORD` with `t ∈ {11, 12, 14}` (xor, and, shl); `(d − 1001)` has
  an inverse (nox's `MAX_DEPTH`: depth only grows by one, so it never
  passes 1000); `CYC += COSTS[t]`. Binary opcodes read `PAIR(body) =
  (a, b)`, push the frame `(b, obj, d, K)` — `COMP1, CONS1, BR, CALL1` or
  `B1(t)` for add, sub, mul, eq, lt, xor, and, shl, look — and evaluate
  `a` at `d + 1`; hash and inv push `(0, 0, 0, K)`, not pushes `B2(13) =
  (tid, obj, 0, K)` (its tag atom stands in as a first operand) and
  evaluate `body`; quote returns `body`; axis reads `ATOM(body) = a`:
  `a = 1` returns `obj`, `a = 0` reads `DIG(obj)` and builds `hash_data`,
  `a ≥ 2` walks.
- **RET** `(val, K)`: `K = 0` is TERM (reads `DIG(val)` = the statement's
  output digest, `CYC = cycles`, no machine row follows); otherwise read
  the frame `K` under the tag of the row's frame flag (B1, B2 arithmetic
  and B2 word carry the frame's op in a column; the tag `64 + op` /
  `96 + op` fixes it, and the op is restricted to its flag's set — B1 to
  the nine B1 opcodes by `(op−5)(op−6)(op−7)(op−9)(op−10)·(op−11)(op−12)
  (op−14)(op−17) = 0` with the first factor a witness column, so a B1 row
  cannot consume another kind of frame) and:
  `CONS1/COMP1/B1` push the successor frame (`B1(op)` pushes `B2(op) =
  (val, obj, 0, parent)`) and evaluate the second child; `CONS2` writes
  `PAIR(new; x, val)`; `COMP2` evaluates the computed formula `val` on the
  computed subject `x`; `BR` reads `ATOM(val) = tv` (0 selects yes) and
  `PAIR(rest)`; `B2 add/sub/mul` read two atoms and write the result atom
  (one-hot add/sub/mul, `Σ sel·code = op`); `B2 eq` reads both operands
  (atoms: compare values; atom vs pair: unequal; pair vs pair: an `EQD`
  row compares `DIG`s limb by limb); `B2 word` (lt, xor, and, not, shl)
  reads two atoms, writes the result atom and hands both operands to 32
  WBIT rows; `B2 look` reads the namespace and key atoms and `STATE(·; ns,
  key, v)`, then a LOOK row; `UHASH` reads `HOP(val)` and builds
  `hash_data`; `UINV` writes `y` with `y·u = 1`; `CALL1` reads
  `ATOM(val)` (the tag is an atom), then witness rows; `CALL2` reads
  `ATOM(val) = 0` (the check accepted) and returns the frame's witness.
- **AXW** walks from the root, one level per row, the most significant
  path bit first: `X` is the address of the node so far (`X' = 2X + c`,
  `node' = c ? r : l` from `PAIR(node)`), `D` the target; the walk ends
  when `2X + c = D`. A counter bounds the walk to 63 levels (`(cnt −
  63)` has an inverse), so the walked integer `I` is below `2^64` and
  `I ≡ a (mod p)`; `I < p` makes `I = a`: below 63 levels `I < 2^63`, and
  at 63 levels the row with `cnt = 62` refuses "bits 62..32 all one and a
  low bit set" (running AND over steps 0..30, OR over steps 31..62, an
  indicator of `cnt = 30` switching between them). Every canonical
  address `2 ≤ a < p` is covered.
- **WBIT** (32 AUX rows per word opcode or lt): four remainders peeled one
  bit per row (`R = bit + 2·R'`, zero after the last row, a counter with
  indicators of `cnt = 0` and `cnt = 31` fixes exactly 32 rows), so each
  starts below `2^32` with its binary digits as bits. xor / and / not:
  `R = (u, w, result, 0)` and the result bit is `a ⊕ b`, `a·b`, `1 − b`;
  shl: `R = (u, n, c', 2h)` with `u·2^(n mod 32) = c' + 2^32·h` checked at
  `cnt = 5` (`2^(n mod 32)` built from the first five bits of `n` by
  repeated squaring; both sides below `2^63 < p`), the result `c'` when the
  remainder of `n` after five bits is zero, else 0; lt (field operands):
  `R0 + 2^32·R2 = u`, `R1 + 2^32·R3 = w` with the canonical check of each
  (high half all ones ⇒ low half zero, on the last row), the comparison
  from the low bit on both halves (the last differing bit decides), result
  `1 − [u < w]`. A word operand `≥ 2^32` has no peel (nox: type error).
- **LOOK** (AUX): reads `PAIR(OBJ) = (R, rest)` and `DIG(R)` = the
  constant digest of `[r0 [r1 [r2 r3]]]`, so the subject carries the
  statement's root at axes 4, 10, 22, 23 (hemera collision resistance,
  as eq); writes the value atom.
- **witness** (AUX, after CALL1): `WATOM` writes `ATOM(new; v)` (any
  `v`) and pushes `CELL(new'; new, sp)`; `WPAIR` pops two cells, writes
  `PAIR(new; l, r)` and pushes it; `WJOIN` reads the only cell (`next =
  0`), writes `PAIR(new; w, obj)` and `CALL2(new'; w, 0, 0, parent)` and
  evaluates the check on `[w obj]` at `d + 1`. Cells carry fresh ids and
  the stack pointer is a state column, so every popped cell is one an
  earlier witness row pushed: the witness is a finite, acyclic noun built
  in post-order, children before parents.
- **HDA / HDB**: `hash_data(h)` = four atoms then three pairs, ids
  `ALLOC..ALLOC+6`.

Sequencing: machine rows chain until TERM; every machine row fixes the
kind (and AUX sub-kind) of its successor; TERM and PAD rows are never
followed by machine rows; the INIT region and the PERM region are forced
by public columns; the first machine row is pinned to `EVAL(fml0, obj0,
K = 0, d = 0, cyc = 0, alloc = P+1)`. Hence the machine rows are exactly
one run from the pinned start to a TERM.

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

- covered: every opcode 0–17 with computed formulas, axis addresses
  `0 ≤ a < p`;
- `eq`: two atoms are compared by value and an atom differs from a pair —
  equal to nox's digest comparison unless hemera collides (nox's identity
  already assumes it does not);
- `call`: the statement claims that a witness exists; the prover supplies
  it (`machine::Hints::witness`), the relation checks the tag is an atom
  and the check returns the atom 0, as nox's `call` with any provider;
- `look`: nox hands the provider the first root limb, the namespace and
  the key; the machine fixes the provider to "the authenticated table of
  the statement's state, read only when all four limbs at axes 4, 10, 22,
  23 equal the statement's root" — state v3's semantics. A provider that
  answers under another root is not modelled; a namespace above 9, a
  missing table or key, a subject without the root noun have no trace (as
  nox's `Unavailable`);
- the arena capacity of `nox::Reduction<N>` is not modelled (the relation
  proves the result of an unbounded arena);
- budget: native nox gives each child of a binary opcode its static
  `bound()` as budget when both bounds fit; "the run succeeds iff
  `cycles ≤ budget`" therefore relies on `bound()` being an upper bound
  of the actual cost (checked for the covered opcodes by review, and by
  the exact-budget tests: `cycles` passes, `cycles − 1` fails).

## soundness status

The relation is tested, not proven: twenty single-opcode programs, 36 lt
and word cases (field extremes `0`, `p − 1`, `2^32 ± 1`, shifts 0, 31,
32, `2^32 − 1`), axis addresses `2^32 + 3 … p − 1` (63-level walks),
calls with atom and pair witnesses, looks over authenticated tables,
joy's compiled `hash.tri` / `add.tri`, an eleven-hash chain, Merkle paths
and long addition trees agree with `nox::reduce` on output and cycles;
every native failure class is a machine failure; tampered traces violate
it; the non-canonical aliases `v + p` of an lt operand and of an axis
address satisfy every constraint but the canonical check
(`machine::tests_ops`). `specs/soundness.md` carries it as a tested row.
