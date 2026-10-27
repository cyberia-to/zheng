---
tags: zheng, audit, recursion, veil, aggregation, privacy
crystal-type: report
crystal-domain: crypto
date: 2026-10-16
---
# block aggregation (G2) — one proof per block, 2026-10-16

Gate G2 of soft3 `proposals/privacy-frozen.md` (§1.8, §2, §5): the block
proof verifies the transactions' zero-knowledge proofs in-circuit, so a
node verifies one constant-size proof per block and transaction proofs
travel only in the mempool. Contract: `specs/aggregation.md`; ledger:
`specs/soundness.md` § block aggregation.

Stand `~/cyber/.stands/G2`: zheng `feat/block-aggregate` (off
`release/0.4` 09308d7), lens `release/0.2` e11eaa8 (unchanged), hemera
`main` d5f0a09 (**hemera 0.3.1**), nox / joy `release/0.4`, strata, tade,
honeycrisp `main`. Apple M4 Max (16 cores, 48 GB), macOS 26.4, rustc
1.95.0, `--release`.

**Every measurement here is on hemera 0.3** (x⁷ full rounds, partial
rounds with an inversion S-box; the recursion circuit's 4-row PERM
gadget). Hemera 0.4 (profile #15: x⁷ every round, 6 + 6 full, 48 partial,
no inversion) lands on `release/0.4` with a reworked gadget; the
aggregation code calls the gadget through `Ops::permute` / `node4` /
`word::verify_leaf` and the sponge and never inlines its rows (veil-r's
width cost model reads `circuit::layout::PERM_ROWS`), so it moves with the
sweep, and every row count and time below is to be re-measured after it.

**Machine load.** Shared with other agents throughout: 1-minute load
average 12–70 during the runs (sampled per run below). Times are upper
bounds of a quiet machine; bytes, rows and SHA-1s are deterministic.

## 1. what was built

| piece | where |
|---|---|
| veil-r: veil's protocol (masked relation, Libra-masked sumchecks, hiding RS tensor opening, PRF coins) on the field-native duplex transcript, the commitment's columns under a field-native 4-ary tree with salted leaves, queries without deduplication, the width chosen for the circuit | `execution/veil/rec/` (`hiding::prove::{rows, messages}` shared with veil) |
| the veil-r verifier written once over `Ops` — native transaction verifier and aggregation leaf | `execution/veil/rec/verify.rs` |
| aggregation programs over `Ops` (leaf, node, top, final) and their digests | `recursion/agg/program.rs` |
| keys (one per level, depth `D`), block prover, native block verifier | `recursion/agg/mod.rs` |
| a wrap level over any verifier program | `wrap::{derive_key_with, prove_with}` (the IVC and wrap paths unchanged) |
| bench, census, keys, bit-flip scan | `examples/block_aggregate` |

## 2. design

```text
mempool   veil-r proof per transaction (SPEND proxy: 357,480 B)
leaf      2^17-row wrap level (1/16, 16 bits): veil-r verified, X = H_TX(vk ‖ pins)
node ×D   2^16-row wrap levels: two children verified, X = H_NODE(X_l ‖ X_r ‖ h)
top       2^15 (1/128, 22 bits): X = H_BLOCK(X_root ‖ N ‖ fields)
final     2^14 (1/512, 26 bits, final mode): X = H_PASS(X_block) — the block proof
node      recomputes X from (vk, every tx's pins, N, fields); verifies one proof
```

*Why a new transaction proof format.* veil v1 hashes its transcript and
its Merkle leaves as bytes (zheng's and lens's byte transcripts, lens's
byte tree); the recursion circuit hashes field elements only. veil-r keeps
veil's IOP and opening message for message and changes only the hashing
(the random oracle of both the soundness and the zero-knowledge
arguments). Consequence for §5 of the proposal: the frozen transaction
proof must be veil-r (or G1's successor on the same transcript), not veil
v1 as reviewed — veil v1 proofs cannot be aggregated.

*Why a tree of wrap levels.* A level's circuit embeds the key root of the
level below, so a fixed-depth tree has one key per level and no
self-reference (the IVC's `live` mechanism is not needed); levels are
independent proofs, so leaves of one block parallelise across devices. A
lone child is verified twice with `h = 0`, which the circuit ties to
`X_r = X_l`; the verifier's canonical tree decides where lone children
are. Blocks of `1..=2^D` transactions share one key set (`D = 7` in the
tables: 128).

## 3. results

The SPEND proxy is veil node-merkle-32 (the proposal's table row "veil,
secret leaf, depth 32, node tree"): relation 2^14 rows, `ℓ = 15`,
degree 7 (outer 8), 5 matrices, 197,048 nonzeros, 3 pins. veil-r on it:
`k = 128`, 261 data rows (`T = 264`), `N = 2^13`, 123 queries, 128.24
proven bits; prove 67–153 ms (Metal / CPU, in-process), native verify
15.0 ms, 357,480 B (veil v1 on the same statement: ~165 KB — §5).

### circuits (`block_aggregate keys 7`, `census 32`)

| level | rows used / 2^n | gates | decompositions | permutations | weakest ledger row |
|---|---|---|---|---|---|
| leaf (veil-r) | 123,932 / 2^17 | 416,189 | 124 | 4,847 | 128.10 (batch combine) |
| node 1 (two leaves) | 55,653 / 2^16 | 84,737 | 310 | 8,307 | 128.09 (shift) |
| node 2..7 (two nodes) | 50,062 / 2^16 | 67,687 | 306 | 7,979 | 128.09 |
| top | 25,033 / 2^15 | 33,842 | 153 | 3,990 | 128.24 |
| final | 16,042 / 2^14 | 20,789 | 105 | 2,606 | 128.40 (fold) |

Leaf by phase (gates / permutations): outer sumcheck 302 / 52, pinned
part `P` 12,633 / 0, inner sumcheck 77 / 16, **free weight `A(0, r)`
189,471 / 0**, **hiding opening 213,706 / 4,779** (per query: two Horner
evaluations of 256 and 383 coefficients, the column's two combinations
over 264 rows, 513 Libra weights, the 268-symbol leaf and a 7-level
4-ary path).

Key derivation, depth 7, all levels: 16.4 s cold on Metal (leaf 4.1 s,
node 6.8 s, top 16.2 s cumulative), 3.5–12.9 s with `ZHENG_KEY_CACHE`.

### the block proof

`block_aggregate block N 7`, transaction proofs seeded per index (so a
block is the same bytes on every backend), one process per row:

| backend | N | load | prove total | leaves (median each) | node levels 1..7 | top | final | bytes | verify (median of 11) | peak RSS |
|---|---|---|---|---|---|---|---|---|---|---|
| Metal | 1 | 26 | 75.6 s | 13.0 s | 6.9, 4.6, 5.6, 7.1, 4.7, 4.0, 5.2 s | 10.3 s | 14.4 s | 61,644 | 2.80 ms | 10.8 GB |
| Metal | 10 | 25 | 203.9 s | 111.0 s (10.17 s) | 28.7, 13.6, 9.6, 5.4, 5.5, 4.1, 4.1 s | 8.7 s | 13.0 s | 62,060 | 3.31 ms | 13.5 GB |
| Metal | 100 | 21–41 | 1,752.7 s | 1,178.6 s (10.93 s) | 339.3, 106.5, 57.0, 28.8, 13.3, 6.7, 3.4 s | 6.1 s | 10.8 s | 61,708 | 3.04 ms | 15.7 GB |
| CPU | 1 | 13–41 | 115.5 s | 17.6 s | 6.8, 6.7, 6.4, 6.3, 6.3, 6.4, 6.3 s | 15.6 s | 37.2 s | 61,644 | 2.49 ms | 15.9 GB |
| CPU | 10 | 43–51 | 267.5 s | 127.3 s (12.61 s) | 33.1, 19.2, 12.9, 6.8, 6.4, 6.4, 6.4 s | 15.7 s | 33.1 s | 62,060 | 2.66 ms | 16.1 GB |
| CPU | 100 | CPU100_LOAD | CPU100_TOTAL | CPU100_LEAVES | CPU100_LEVELS | CPU100_TOP | CPU100_FINAL | CPU100_BYTES | CPU100_VERIFY | CPU100_RSS |

Verify = parse, the statement's digests (N leaf sponges, the tree, block,
pass) and the final level natively. Byte identity: SHA-1 of the block
proof — N = 1 `a9d15002…` Metal = CPU; N = 10 `89d72804…` Metal = CPU;
N = 100 `08204a62…` Metal BYTEID100.

Per transaction at N = 100 on Metal: 17.5 s (leaf 10.9 s + its share of
the node levels 5.5 s + the fixed top/final 0.2 s). The hard bound of the
final proof: **62,892 B** (`wrap::wire::max_bytes` of the final key; ≤ 64
KiB = 65,536, checked by `AggKeys::derive`).

## 4. the 100-transaction target

**Target: 100 transactions per 30 s block on one M4 Max-class machine.
Measured: 1,752.7 s on Metal under load (≈ 58× short).** On a quiet
machine the wrap prover runs ≈ 50 µs a row (`ivc-speed-2`: 3.3 s at 2^16),
which puts this design at ≈ 9.8 s a transaction (2^17 leaf + 2^16 node a
transaction, padded rows) — ≈ 980 s per 100, ≈ 33× short.

What moves it, by measured or derived row counts (padded rows per
transaction, today ≈ 196,608):

| lever | effect on the leaf | rows / tx | status |
|---|---|---|---|
| defer the matrix claims (`A(0, r)` as five claims carried up the tree, folded along lines at each node, evaluated once by the block verifier, as the IVC defers `G`) | −189,471 gates (−47k rows) | — (alone: 76k rows, still 2^17) | designed (`aggregation.md` § not built) |
| Libra weights in closed form (per round `λ·y^c·(1 + t·y + t²·y²)·Σ (x_i y³)^d`) | −≈ 40k gates (−10k rows) | with the above: ≈ 65k → 2^16 borderline | estimated |
| two transactions a leaf after both (2 × 65k in 2^17) | nodes halve | ≈ 98k | estimated |
| hiding WHIR transaction proofs (G1's route): the opening becomes a field-native WHIR verify (the inner wrap's is ≈ 25k rows for a 2^16 word) | opening 53k + 19k rows → ≈ 25k | ≈ 49k (4 a leaf) | depends on G1 |
| prover speed: commitments' hashing ≈ 70 % of a wrap level (`ivc-speed-2`); kernel-only gains measured at ≤ 1.44× | — | — | measured ceiling |

Even with every row lever (≈ 49k rows a transaction, 4.9M rows per 100),
the prover at today's ≈ 50 µs a row needs ≈ 245 s per block: **8× short
of 30 s on one machine.** Reaching it takes one of: (a) a ≈ 8× faster
wrap prover (≈ 6 µs a row — beyond the kernel work measured so far), (b)
8–10 machines proving leaves in parallel (the tree's leaves and each
level's nodes are independent; the top and final add ≈ 17 s, so even (b)
needs a faster top/final for 30 s), or (c) aggregation by accumulation
instead of recursion per transaction: fold the transaction proofs'
opening claims into one accumulator (per transaction the cost of hashing
its opened data, ≈ 5k permutations, rather than proving a 2^17-row
circuit) and decide once per block. (c) is the structural answer; it is
the accumulation of `accumulation.md` applied to veil-r openings and is
research-grade work, not tuning.

## 5. what the transaction proof costs

veil-r at the SPEND proxy is 357,480 B (veil v1 ≈ 165 KB): queries are
not deduplicated (123 full 4-ary paths, ≈ 75 KB) and the circuit-optimal
width `k = 128` makes columns long (123 × 268 limbs ≈ 264 KB). The
mempool pays it; the block budget never sees it (§1.8). Levers: a
multi-opening wire (shared path nodes; the verifier is unchanged — the
parser expands), a wider `k` (fewer column limbs, a larger circuit:
`k = 256` halves the columns and doubles the Horner work).

## 6. self-review

SELF_REVIEW

## 7. runs

RUNS

## 8. commands

```text
cargo run --release -p zheng --features test-hooks --example block_aggregate -- census 32
ZHENG_KEY_CACHE=<dir> … block_aggregate keys 7
ZHENG_BACKEND=metal|cpu ZHENG_KEY_CACHE=<dir> ZHENG_BLOCK_OUT=<dir> … block_aggregate block <N> 7
… block_aggregate flip <dir>/block-10-d7-metal.bin 10 7
cargo test --release -p zheng --features test-hooks --lib agg:: rec::
cargo test --release -p zheng --features test-hooks --test block_aggregate
```
