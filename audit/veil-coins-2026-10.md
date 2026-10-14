---
tags: zheng, audit, zk, veil, randomness, performance
crystal-type: report
crystal-domain: crypto
date: 2026-10-14
---
# veil prover coins: counter-mode PRF, parallel fills — 2026-10-14

Fast-path task 2(b) for the zk profile (envelope profile 2, scheme `veil`).
The soft3 audit of 2026-10-14 measured veil secret-leaf Merkle proofs at
0.94 s (depth 16) / 2.0 s (depth 32) on Metal, 295–545 KB, and attributed
~45% of the veil prover to the hiding commitment's sequential randomness.
Branch `feat/fast-path-2-veil` off `release/0.4` (aa54bdd). Siblings: hemera
d5f0a09, lens ff2c160 (`feat/fast-path-2`), strata 494df7a. Apple M4 Max,
16 cores, rustc 1.95.0, `--release`. **The machine was shared and heavily
loaded (load average 26–118 during this work); every table states the load
at the time it was taken; times are medians.**

## 1. where the time went (before)

`ZHENG_TIMING=1` laps added to `veil::protocol::prove` and
`veil::hiding::commit` (ms per phase, Metal, load ≈ 31, one proof each; the
rest of the wall time is `prepare_execution`):

| phase | depth 16 | depth 32 |
|---|---|---|
| setup, masking-row fill, Libra masks | 21 | 60 |
| commit: data rows + row padding `ν_i` + `m_a, m_b, m_P` | 219 | 473 |
| commit: encode (one device dispatch per row) | 118 | 306 |
| commit: column salts (`N × 4`) | 215 | 451 |
| commit: Merkle tree (lens) | 152 | 478 |
| sumchecks + opening | 116 | 303 |
| **inside `prove`** | **840** | **2,071** |

Shape at depth 32: `k = 2048`, 257 data rows + 3 masking rows, `N = 2^17`,
123 queries. Row padding, masks and salts took 924 of 2,071 ms (45%): one
hemera keyed-XOF permutation per 32 bytes, rejection-sampled 8 bytes at a
time, on one thread.

## 2. construction

`rs/src/execution/veil/coins.rs`.

- Seed: 32 bytes from `getrandom` (zeroized), or `Coins::seeded` in tests.
- Key: `K = derive_key("zheng-veil-coins-v2", seed)`, read as four
  Goldilocks lanes (hemera digests carry canonical lanes); kept in
  `Zeroizing<[u64; 4]>`.
- Block `b` of stream `label`: the first eight lanes of
  `permute_ct(K0 K1 K2 K3 ‖ label ‖ b ‖ 0 × 9 ‖ TAG)`, `TAG` = ASCII
  `"veilcoin"` mod p in lane 15. Lanes 8–15 of the output (512 bits) are
  never revealed.
- Element `i` of a stream is lane `i mod 8` of block `⌊i/8⌋`; an `Fp3`
  element is three consecutive base elements.
- Every block is a pure function of `(K, label, b)`, so `Coins::fill` splits
  a vector over `par::chunks_mut` (honours `ZHENG_THREADS`), each thread
  computing its own blocks (`fill_at(label, offset, out)`); the result is
  the sequential fill for any thread count or chunking.

Label table (one stream per consumer; inputs `(label, b)` never repeat
across consumers):

| label | consumer | element layout |
|---|---|---|
| 1 `PAD_FILL` | `pad::Extension::witness` — free values of the masking rows | fill order |
| 2 `LIBRA_G1` | `libra::Mask` of the outer sumcheck | round-major coefficients, 3 limbs each |
| 3 `LIBRA_G2` | `libra::Mask` of the inner sumcheck | as `g1` |
| 4 `ROW_PAD` | hiding commitment, padding `ν_i` of data row `i` | `i·k + c` = coefficient `k + c` of row `i` |
| 5 `MASK_A` | masking row `m_a` | `K` coefficients |
| 6 `MASK_B` | masking row `m_b` | `k − 1` coefficients |
| 7 `MASK_P` | masking row `m_P` | `K` coefficients |
| 8 `SALT` | column salts | `4j + s` = limb `s` of column `j` |
| `≥ 2^32` | tests only | — |

Data rows are built in threads (each row copies its entries and fills its
`ν_i` with `fill_at(ROW_PAD, i·k, …)`). The codeword rows are now encoded
one row per thread on the CPU when more than one thread is available
(`encode_base_with(…, false)`); with one thread the backend's per-row path
is kept. Measured (laps, load ≈ 28, two runs each): depth 32 encode 149 →
84–86 ms on Metal, 180 → 76–84 ms on the CPU backend; depth 12 on the CPU
backend 57–65 → 21–22 ms.

## 3. why the coins stay uniform and independent

Every element is a whole output lane of the permutation — a field element
— so there is no sampling bias to bound and no rejection.

Model: hemera's Poseidon2 permutation `π` on `F_p^16` as an ideal
(uniformly random) permutation, the same heuristic under which hemera's
sponge is used as a random oracle throughout the soundness ledger. Let `D`
be a distinguisher with forward/inverse access to `π` (`N` queries) and to
an oracle `O` answering the `q` distinct block inputs a proof uses, either
`O(x) = trunc_8(π(K ‖ x))` (real) or independent uniform elements of
`F_p^8` (ideal). Lazy-sample `π`; the two games differ only on:

1. a forward query of `D` whose first four lanes equal `K`:
   `≤ N / (p^4 − N)`;
2. an inverse query of `D` on a full construction output, which needs its
   eight hidden lanes: `≤ N·q / (p^8 − q − N)`;
3. without 1–2, the `q` outputs are distinct uniform points of `F_p^16`
   sampled without replacement, versus with replacement: `≤ (q + N)² / p^16`;
   truncation of a uniform point of `F_p^16` to eight lanes is uniform on
   `F_p^8`.

So `Adv_PRF ≤ N/p^4 + N·q/p^8 + (q + N)²/p^16` (up to the `−N` in the
denominators), plus `N / 2^256` for `D` having queried `derive_key` on the
seed itself (the key is then uniform on `F_p^4` with `derive_key` as a
random oracle). With `p^4 ≈ 2^255.99`: a depth-32 proof draws
`q ≈ 1.33·10^5 ≈ 2^17` blocks (65,792 row padding, 65,536 salts, 1,280
masks, the rest < 100); at `N = 2^80` the bound is `≈ 2^-175`, and at
`N = 2^128` it is `≈ 2^-127`, dominated by key guessing, independent of
`q`. Fresh seeds per proof add a union over proofs to term 1 only.

Independence across consumers follows from the same argument: all streams
are outputs of one PRF on distinct inputs, which the bound already treats
as one oracle.

## 4. why the HVZK statement is unaffected

The ledger's zero-knowledge row (`specs/soundness.md` § zk) proves
honest-verifier statistical zero knowledge of the interactive protocol for
**uniform** prover coins, with a simulator `S` given only the public
statement and `V`; distance `≤ ε_v + 2/p³ + Q·2^-256`. Neither the protocol
nor `S` changes. Any distinguisher between transcripts of the PRF-coined
prover and those of the uniform-coined prover yields a PRF distinguisher
with the same advantage (the reduction runs the prover on the fixed
witness, drawing coins from `O`), so the distance to `S` grows by exactly
`Adv_PRF` (§3). In the ideal-permutation model the result stays
information-theoretic against distinguishers bounded to `N` hemera queries;
this is the model the ledger already uses for salted leaves and
Fiat–Shamir. The construction it replaces (a hemera keyed XOF from the same
256-bit seed) had the same character; the ledger row now names the term.

## 5. constant time

- Seed and key: `getrandom` into `Zeroizing`, hemera `derive_key` (constant
  time per hemera `specs/api.md` § constant time).
- Block: the input is assembled by fixed lane writes, `permute_ct` is
  hemera's constant-time kernel, the output lanes are read through hemera's
  masked canonicalisation (`as_canonical_u64`: mask, no branch); the state
  is overwritten after use (best effort, through `black_box`). Positions,
  block indices and loop bounds depend only on public lengths and offsets.
- The old construction branched on secret bytes in its rejection loop
  (`v < p`, taken with probability ≈ 2^-32 per element); the new one has no
  secret-dependent branch.
- Downstream is unchanged and not constant time, as the module doc states:
  nebu arithmetic on masked values, RS encoding, and the lens Merkle tree
  over secret-derived codeword columns. lens `rspcs/src/merkle.rs`
  `Tree::build` is threaded already: CPU path = `par_map_min` over groups of
  256 leaves through hemera `hash_leaf_batch` (fast kernel, whose
  multiplication reduction takes a predicted branch with probability
  ≈ 2^-32); device path (≥ 4,096 leaves on Metal/WebGPU) = leaf bytes and
  absorption on CPU threads, permutations on the GPU. Constant-time leaves
  would need a lens change (a tree built with a constant-time batch
  kernel); not made here.

The tree is not single-threaded, so it was not parallelised further. A
zheng-side column-major leaf layout (blocked transpose, salts filled per
tile) was prototyped and measured (two runs each, Metal, load ≈ 27): tree
lap 497 / 290 ms against 498 / 297 ms, transpose + salts 44 / 39 ms against
salts alone 36 / 42 ms — no gain, reverted. The tree is
permutation-bound: at depth 32 a leaf is 264 elements (2,112 bytes, 38
sponge blocks), `2^17` leaves ≈ 5.1M permutations.

## 6. measurements

`cargo build --release -p zheng --example fast_path`, then
`ZHENG_BACKEND=metal FAST_REPS=3 fast_path veil-merkle-12 veil-merkle-16
veil-merkle-32 veil-hash.tri`, before (aa54bdd) and after (624db5f) binaries
interleaved, three rounds; cell = median of the three round medians (each
of 3 proofs). Prove ms is wall time of `veil::prove` including
`prepare_execution`; bytes = proof bytes (varies ±1.5 KB between proofs
through deduplicated openings).

Load average during the rounds 32.6 → 28.9 (1-min), 55 → 50 (5-min):

| fixture | before prove ms | after prove ms | speedup | before B | after B | verify ms (both) |
|---|---|---|---|---|---|---|
| veil-merkle-12 | 797.4 | 411.6 | 1.94× | 293,173 | 293,333 | 150–160 |
| veil-merkle-16 | 1,087.6 | 602.4 | 1.81× | 419,013 | 419,429 | 195–215 |
| veil-merkle-32 | 2,197.7 | 1,185.5 | 1.85× | 546,261 | 545,685 | 377–421 |
| veil-hash.tri | 71.9 | 34.0 | 2.11× | 63,205 | 63,061 | 7.8–8.7 |

CPU backend, one round, load ≈ 29.5: merkle-12 928.5 → 578.2 ms, merkle-32
2,859.6 → 1,762.1 ms. An earlier round at load ≈ 70–80 (other agents'
work): merkle-32 4,474.8 / 4,643.4 → 2,240.4 / 2,137.7 ms. The verifier is
untouched (verify times are noise between rounds).

After, inside `prove` at depth 32 (Metal, load ≈ 31): setup + pad + masks
44 ms, row padding + masks 26, encode 83, salts 25, tree 375, sumchecks
113, open 129 — the coins are now ≈ 50 ms of ≈ 795 ms; the tree is the
largest part.

## 7. proof size

Composition at depth 32 (545,685 B): opened columns 123 × 264 × 8 ≈
259.8 KB (48%), `p_P` (`K = 4096` Fp3) 98.3 KB (18%), `q` (`3k − 1 = 6143`
Fp3) 147.4 KB (27%), Merkle siblings and the rest ≈ 40 KB. The opening is
in the unique-decoding regime: one query buys at most 1 bit
(`(1 + (2K − 1)/N)/2`), so ≈ 112–135 queries are needed whatever the rate.

Parameter sweep (proofs produced and verified by `fast_path` with the
parameters overridden in a throwaway build; every set admitted by the
verifier; bits = `Config::security_bits` at depth 32, recomputed). Load
average 62 → 43 over the sweep, so prove ms are indicative only:

| rate, grind | queries | bits | merkle-12 B | merkle-16 B | merkle-32 B | prove ms 12 / 16 / 32 |
|---|---|---|---|---|---|---|
| 1/32, 16 (default) | 123 | 128.24 | 293,557 | 418,213 | 546,485 | 774 / 1,070 / 2,259 |
| 1/16, 16 | 135 | 128.06 | 303,157 | 431,589 | 571,381 | 643 / 973 / 1,734 |
| 1/64, 16 | 118 | 128.76 | 290,901 | 411,045 | 538,069 | 894 / 1,275 / 2,347 |
| 1/128, 16 | 115 | 128.43 | 289,877 | 407,301 | 535,061 | 630 / 958 / 2,054 |
| 1/32, 20 | 119 | 128.59 | 288,789 | 410,565 | 536,949 | 417 / 560 / 1,040 |
| 1/32, 24 | 114 | 128.03 | 281,877 | 398,149 | 525,365 | 641 / 840 / 1,254 |
| 1/64, 24 | 109 | 128.16 | 278,773 | 389,861 | 516,725 | 539 / 969 / 1,952 |
| 1/16, 24 | 126 | 128.59 | 292,245 | 419,653 | 549,301 | 457 / 864 / 998 |
| 1/8, 30 | 145 | 128.32 | 312,757 | 439,397 | 586,197 | 9,747 / 5,687 / 23,968 |

hash.tri at load ≈ 33 (7 proofs each, two rounds): 1/32-16 33.4 / 35.8 ms,
64,261 / 63,925 B; 1/32-24 280.3 / 409.4 ms, 60,693 / 61,045 B; 1/64-24
145.3 / 224.9 ms, 63,109 / 61,925 B.

Finding: parameters move the size by at most −5.4% (1/64 with 24 grinding
bits), and 24 grinding bits cost 0.1–0.4 s of expected grinding, which
multiplies the small proofs' time (hash.tri 34 → 280–410 ms). **Defaults
unchanged** (rate 1/32, 16 grinding bits, 128.24 proven bits).

Masked polynomials:

- `m_b` is one codeword row: 8 B per opened column (≈ 1 KB per proof) plus
  `k − 1` coins. It one-time-pads the `k − 1` coefficients of `q` above
  `X^K`; dropping it would need a new argument that those coefficients
  (linear forms in the row padding) leak nothing jointly with the opened
  columns. ≈ 0.2% — not worth the proof obligation.
- `g1`, `g2` (Libra) occupy `log m·(d + 1)·3 + ℓ·9` entries (hundreds)
  among ≈ 5·10^5 committed entries: no measurable size effect.

Where the size actually is, with estimates (not implemented):

| change | estimate at depth 12 / 16 / 32 | needs |
|---|---|---|
| row padding of `t + 1` coefficients instead of `k` (`K = k + t + 1`, encoded zero-padded to `2k`): `p_P` and `q` shrink from `5k` to `≈ 3k + 2t` Fp3, `D = 2K` drops so ≈ 5 fewer queries | −48 KB (−16%) / −54 KB (−13%) / −102 KB (−19%) | wire `VERSION` 2, prover + verifier degree bounds, ledger rows for soundness (`D`) and zk (padding `≥ t`); same encoding cost |
| list-decoding (Johnson-regime) analysis of the opening: ≈ 2.4 bits per query at rate 1/32 instead of ≤ 1 → ≈ 47 queries | columns 260 → ≈ 100 KB at depth 32; total ≈ 300 KB before re-optimising `k` | a new soundness proof of the zero-knowledge linear test beyond unique decoding (proximity gaps up to Johnson are proven, BCIKS20; the `q` agreement argument is not) |
| hiding WHIR in place of the tensor commitment | succinct (WHIR, non-hiding) merkle-32 is 63,594 B envelope at 128.04 bits (measured here, load ≈ 31); a hiding variant (masking polynomial committed alongside, salted leaves, masked sumcheck) ≈ 1.5–2.5× → ≈ 95–160 KB vs 545 KB, verify near the succinct profile's | a hiding WHIR construction and its zk proof; not built |

## 8. tests

- `veil::coins::tests` (new, 6): fixed seed reproduces and seeds differ
  (incl. one-bit seed change); OS coins differ; element `i` = lane `i mod 8`
  of block `⌊i/8⌋`, input layout checked against the plain permutation;
  parallel fill = sequential `fill_at` = every chunking (1, 3, 8, 13, 1000)
  = explicit 2/3/5/16-thread splits = the sequential reader, for lengths
  0 … 50,001; labels and blocks separated (4,096 lanes over 8 labels × 64
  blocks, all distinct); uniformity over 2^17 elements: chi-square on the
  low 8 bits and on `⌊256·v/p⌋` (255 d.o.f., accepted in (160, 370)), no
  repeated element, top bit within ±2,000 of n/2.
- `veil::tests::seeded_proofs_do_not_depend_on_the_thread_count` (new):
  golden hemera digest of a seeded proof, identical under
  `ZHENG_THREADS=1, 2, 3, 7, 16` and unset.
- `cargo test --release -p zheng veil`: 20 passed (lib); `zk`: 11 passed
  (lib) + 1 (`veil_profile`); `--test reaudit_private`: 3 passed, 1
  ignored; `--test veil_profile`: 2 passed (veil proof 63,861 B median of
  11, verify 8.5 ms).
- Bit-flip scan, `cargo test --release --test veil_profile -- --ignored`:
  zk envelope (hash with secret preimage) 63,448 B, **507,584 flips, 0
  accepted**, 739 s (load 32 → 88).

## 9. open

- Constant-time Merkle leaves over secret-derived columns need a lens
  change (§5); the prover as a whole stays non-constant-time.
- The tree (≈ 375–500 ms at depth 32) is now the largest veil prover
  cost; it is permutation-bound in lens.
- The `K = k + t + 1` padding change (−13 to −19% bytes, fewer coins and
  smaller polynomials) is the cheapest real size lever; it is a wire and
  ledger change and was left for a decision.

## independent review

pending (coordinator)
