---
tags: zheng, audit, recursion, wrap, performance
crystal-type: audit
crystal-domain: crypto
---
# wrap chain — prover memory and time, verifier time, 2026-10-10

Follow-up to `audit/wrap-2026-10.md` (zheng #56, `feat/wrap` 606cda1).
Goals: the final proof verifies in ≤ 1 ms, stays ≤ 64 KB, every ledger
row ≥ 128 bits (grinding priced; interactive figures stated); the wrap
chain proves in seconds, not 13–20 minutes, in far less than 32–38 GB.
Branch `feat/wrap-fastverify` (stand `.stands/V`: B's siblings, lens
`feat/field-native-whir` c91f55a, hemera cf28a64). Apple M4 Max (12 P +
4 E cores), 48 GB, rustc 1.95.0, `--release`.

**Machine load.** The machine was shared with other agents during every
run: load average 22–103 (sampled per run below). Wall-clock times are
upper bounds and vary 2–5× between runs of the same binary; the tables
give the run's load. A verifier's one-thread CPU time (`clock_gettime`
of the verifying thread) is load-independent up to core type (P vs E)
and is reported beside wall time. Sizes and permutation counts are
deterministic.

## 1. what changed

| change | where | effect |
|---|---|---|
| streamed codewords: above `2^25` symbols a word is committed coset by coset (every symbol of a leaf lies in one coset of the order-`2^ℓ` subgroup: one NTT per coset, its leaves hashed, the values dropped); an opening recomputes its leaf from the coefficients (`O(2^ℓ)` per leaf) | `recursion/stream.rs`, `word.rs` | prover memory: no codeword is held (a 1/512 word of `2^20` cells was 4 GB, its interleaving copy another 4 GB) |
| key words committed once per key (were recommitted per proof) | `wrap/mod.rs` (`WrapKey::kw`), `wrap/prove.rs` | the inner levels' largest commitments leave the prover |
| chain `4i:16,8i,9f:24` (was `6i,8i,8f:30`): the first level at rate 1/16 grinding 16 bits; the final level at rate 1/512 grinding 24 bits (was 1/256 at 30) | `wrap::SHIPPED`; planned with `examples/wrap_plan`, `examples/wrap_chain` (shape-only keys, seconds) | grinding work of the final level from ≈ 2^32.8 to ≈ 2^26.6 permutations; the first level's codewords 4× smaller |
| parallel sumcheck rounds and folds; split eq-term tables (`eq(p_lo)·eq(p_hi)` per block, parallel) | `accumulate/sumcheck.rs` | the batch sumchecks of every opening and the accumulation step leave one core |
| final level: final polynomial and the column values at `ρ`/successor absorbed as message digests (8 part sponges + one, tag `MSG`) — a transcript change of the final level only | `recursion/msg.rs`, `whir/verify.rs`, `wrap/verify.rs` | the verifier's serial permutations from 206 to 107 |
| verifier: closing check of `u_λ` slot by slot (one product per slot, interleaved Horner over reads); constraint graph pruned and compiled (7,506 operations); only the 64 key columns `G` reads (of 108); Merkle chains split over threads; multi-openings' leaf digests batched and their trees expanded in parallel; a persistent worker pool instead of per-pass threads | `wrap/wiring.rs`, `air/num.rs` (`Compiled`), `ops.rs`, `whir/wire.rs`, `recursion/pool.rs` | below |
| verifying keys as bytes (`WrapKey::vk_bytes`, `from_vk_bytes`, `vk_digest`; 9.0 MB for the final level); a loaded key verifies and does not prove | `wrap/vk.rs`, `examples/wrap_verify` | a verifier starts in ≈ 0.1 s instead of deriving the chain (≈ 3 min) |

Wire format: the final proof's byte layout is unchanged (same fields,
same order); its shapes follow the new parameters (final level 1/512, 24
grinding bits: round queries 24 / 18 / 15) and its transcript absorbs two
messages as digests, so proofs of `feat/wrap` and of this branch do not
verify under each other's keys. Envelope profile 6 must take the new
final key (the chain `wrap::SHIPPED`).

## 2. gates

Fixture add.tri (7, 5), 33 cycles, one IVC step (IVC proof stored and
reused, `ZHENG_IVC_DIR`). Before: `audit/wrap-2026-10.md` (same machine,
load 13–40). After: this branch, chain `4i:16,8i,9f:24`.

| gate | before (`audit/wrap-2026-10.md`, chain `6i,8i,8f:30`) | after (chain `4i:16,8i,9f:24`) | goal |
|---|---|---|---|
| final proof bytes | 62,589 | **63,865** (header 49 · nox-public claim 1,272 · AIR 4,736 · opening 57,808) | ≤ 65,536 — met |
| verify, 1 thread, warm (statement prepared, parse included) | 10.1–10.9 ms wall | **5.3–5.7 ms** (median of 41; the verifying thread's CPU time; wall 5.3–5.9 ms at load 37–45) | ≤ 1 ms — missed (×5) |
| verify, 1 thread, cold (first verification of a fresh process, key loaded from bytes) | — | 6.3–7.0 ms wall | — |
| verify, 16 threads, warm | 6.4–7.2 ms wall | median 6.2–8.6 ms wall, **min 2.8 ms** (41 runs, load 37–60: the machine never had 16 idle cores; not a quiet-machine figure) | ≤ 1 ms — missed |
| verify, 16 threads, cold | — | 7.8–8.4 ms wall (load ≈ 40) | — |
| verifying key | derived (the whole chain, ≈ 6 min) | 8,978,744 B, loaded and compiled in 5.8 ms | — |
| IVC prove (stored, reused by the chain) | 26.8 s | 44.3 s at load 78 (the calling thread's CPU 4.2 s) | — |
| wrap 0 / 1 / 2 prove | 84.5 / 168.4 / 731.9 s | **11.8 / 42.5 / 28.7 s** (one run, load 24–41) | seconds |
| wrap chain prove | 984.8 s (16.4 min) | **83.0 s** | seconds — 12× faster, not yet seconds |
| key derivation (once per chain, not per proof) | ≈ 360 s | 17.3 + 140.9 + 0.9 s (the 1/256 level's key words, Fp3, 2^29 points) | — |
| peak memory | 32–38 GB max RSS (45.7–61.3 GB footprint) | **19.5 GB** max RSS, 14.1 GB footprint (keys of every level held: ≈ 7 GB before proving starts) | — |
| ledger | weakest 128.24 / 128.29 / 128.02 | weakest 128.22 / 128.29 / 128.40 | ≥ 128 — met |
| interactive (no grinding) | 104.42 / 104.29 / 98.02 (the combination's grinding not counted) | 109.34 / 104.29 / 104.70 (fold, query and combination grinding removed) | stated |
| bit-flip scan of the final proof | 500,712 flips, 0 accepted | **510,920 flips, 510,104 decoded, 0 accepted**, 0 panics — twice (562 s; 682 s on the final verifier code, with the permutation recall and the packed closing) | 0 — met |

Permutations per verification (deterministic): before ≈ 1,000 batched +
the transcript's (not counted); after **107 one at a time + 1,500
batched** (the parse's multi-opening expansion; the verifier's Merkle
check reads those permutations instead of recomputing them).

## 3. ledger

`wrap::ledger` per level (`recursion::wrap::review::the_shipped_wrap_levels_reach_128_bits_and_their_interactive_rows_are_stated`):

| level | rows | queries per round | weakest (grinding priced) | interactive weakest |
|---|---|---|---|---|
| inner 1/16, grinding 16 (combination 19), `n = 16` | 53,042 → 2^16 | 58 / 33 / 23 / 18 | shift_2 128.22 | 109.34 |
| inner 1/256, grinding 24 (combination 24), `n = 15` | 26,089 → 2^15 | 27 / 20 / 16 / 13 | shift_1 128.29 | 104.29 |
| final 1/512, grinding 24, `n = 14`, `ℓ = 20` | 15,606 → 2^14 | 24 / 18 / 15 | fold_1 128.40 | 104.70 (shift_1; fold_1 106.40) |

The final level's rate cannot rise further without grinding above 24
bits: at 1/1024 the Johnson-regime fold terms (BCGM MCA error grows with
the domain) need 25+ bits per fold challenge (`wrap_plan 14 10 …`). At
1/256 with 20–22 grinding bits the opening alone is 61–62 KB (with the
6 KB of header, claim and AIR, over 64 KB). The inner 1/256 level is
fixed by the final circuit: at 1/128 the final circuit outgrows 2^14
rows (`wrap_chain 6i,7i,9f:24`).

New row: final-level message digests (`soundness.md`): binding is the
hash row's collision resistance.

## 4. where the time goes now

Prove, chain `4i:16,8i,9f:24` (wall, load 24–41; `ZHENG_TIMING`):

| level | commit (trace words) | zerocheck | opening | of the opening |
|---|---|---|---|---|
| inner 1/16, 2^16 | 2.7 s | 3.5 s | 5.5 s | round-1 commit 2.1 s; grinding < 0.5 s |
| inner 1/256, 2^15 | 17.2 s (two base words, 2^29 points each) | 1.7 s | 23.5 s | combination grinding (24 bits) 2.9 s, round-1 commit (Fp3, 2^28 points) 8.3 s, round-2 4.0 s, query and fold grinding 5.4 s |
| final 1/512, 2^14 | 8.0 s (one word, 2^29 points) | 0.7 s | 19.9 s | fold grinding 1.5 + 1.7 + 0.6 s, round-1 commit (Fp3, 2^28 points) 8.8 s, query grinding 2.9 s, round-2 commit 4.1 s |

Hashing the commitments (leaf sponges and tree nodes, hemera batched)
is ≈ 70 % of the chain (≈ 59 of 83 s), grinding ≈ 20 % (≈ 15 s); both are the GPU backend's
(`feat/gpu-backend`). Per proof the calling thread's CPU is 1–3 s a
level: the rest runs on every core.

Verify, one thread, CPU time of the verifying thread (`ZHENG_TIMING`,
add.tri): parse 1.5 ms (decoding; expanding the multi-openings: 1,460
batched permutations), the nox-public claim 0.06, the public digest
0.12, zerocheck 0.12, the key's 64 used columns at `ρ` 0.5–0.9, the
constraint graph (7,506 operations) 0.05–0.15, the opening's rounds and
final queries 0.6 (transcript: 107 single permutations ≈ 0.31 ms of
hemera's 2.9 µs latency), the closing check 2.3 (the wiring `u_λ` over
49,333 reads and 23,892 writes: one Fp3 product per slot), the Merkle
check 0.1 (the parse's permutations recalled). On 16 threads the
closing, the key, the Merkle checks and the expansion of the three trees
run in parallel; what stays on one thread is ≈ 1–1.3 ms (the transcript,
decoding, zerocheck, the round-0 tree's expansion, the public digest) —
the floor of this design on a quiet machine, above the 1 ms goal.

## 5. checks

| check | result |
|---|---|
| `cargo test --release -p zheng --lib` | 280 passed, 3 ignored |
| `tests/wrap.rs` (chain at 1/16, final mode) | passed, 122 s, 12.0 GB max RSS |
| `tests/wrap_review.rs` (546 tampers) | passed, 129 s, 9.9 GB max RSS |
| `wrap::ledger` tests (`every_ledger_row_of_the_wrap_profiles_reaches_128_bits`, the shipped chain's) | passed |
| streamed words = held words (`stream::tests`, `word::tests::streamed_leaf_digests_equal_the_held_codeword_s`) | passed |
| message digest native = over `Ops` (`msg::tests`) | passed |
| bit-flip scan (`wrap_flip add.tri`) | 510,920 flips, 0 accepted (twice; the second on the final code) |
| verifying key bytes round trip (`wrap_verify`) | re-serialised bytes equal |

## 6. what is left

- **verify ≤ 1 ms**: missed. One thread 5.3–5.7 ms; sixteen threads
  min 2.8 ms under load, ≈ 1–1.3 ms of single-thread work left. Levers:
  fewer serial transcript permutations (zerocheck messages, fold rounds:
  a lower-latency single permutation — hemera's inverse chain is 2.2 of
  its 2.9 µs — or fewer rounds); the round-0 tree's expansion (≈ 0.45 ms,
  one level at a time); decoding without per-query clones; a quiet
  machine to measure on.
- **prove in seconds**: 83 s for the chain (from 985 s), IVC 27–44 s
  per step. Hashing and grinding dominate (GPU backend). Algorithmic
  levers not taken: a rate-12 leaf sponge (Fp3 leaves 6 → 4
  permutations; changes the circuit's permutation rows); the inner 1/256
  level's key words in the base field (key columns split in limbs: the
  key group's leaf 11 → 4 permutations in the final circuit, room to
  lower that level's rate); IVC grinding (22–24 bits per challenge, half
  of the decider's time) needs the step circuit re-fitted.
- **memory**: 19.5 GB peak, ≈ 7 GB of it the keys of every level (the
  IVC key's held key words, the 1/256 key words' tree). A prover that
  holds only the next level's key would stay near 10 GB.
- rec-16 not re-run (its IVC proof is 45 min); proof sizes and the final
  circuit are flat in the run length (`audit/wrap-2026-10.md`).
- the deferred nox-public claim still travels (1,272 B).

## 7. second round, 2026-10-13 (after the review merge, 5ec724e and later)

Measured on a nearly quiet machine (1-minute load 4–8 at the start of
each run; the chain's run rose to 28). Same fixture (add.tri), chain
`wrap::SHIPPED` = `4i:16,8i:24,9f:24`, IVC at `ivc::SHIPPED_POW` = 16.

| gate | #56 (`audit/wrap-2026-10.md`) | §2 of this audit (2026-10-10, loaded) | now (quiet) |
|---|---|---|---|
| final proof | 62,589 B | 63,865 B | **64,217 B** (this proof; the size varies with the queries' shared Merkle nodes: 63,257–64,217 B over three proofs of this chain; a simulation of the sibling counts over 200,000 transcripts puts the largest ≈ 32 siblings (≈ 1 KB) above the mean — not a deterministic bound) |
| verify 16 threads, warm | 6.4–7.2 ms | 6.2–8.6 ms (load 37–60) | **2.46–2.55 ms** median of 41 (min 2.34) |
| verify 16 threads, cold | — | 7.8–8.4 ms | **3.4–3.8 ms** |
| verify 1 thread, warm | 10.1–10.9 ms | 5.3–5.7 ms (CPU) | **5.12–5.30 ms** |
| verify 1 thread, cold | — | 6.3–7.0 ms | **6.0–6.3 ms** |
| IVC prove, add.tri (one 2^15 step + decider) | 26.8 s | 44.3 s (load 78) | **15.0 s**: step 8.4 s (word a 0.8, zerocheck 3.6), decider 6.6 s; at 24 grinding bits on this code 29.2 s (step 13.4, decider 14.9) |
| wrap 0 / 1 / 2 prove | 84.5 / 168.4 / 731.9 s | 11.8 / 42.5 / 28.7 s (load 24–41) | **11.8 / 50.6 / 34.5 s** (load 5 → 28 during the run) |
| key derivation (once) | ≈ 360 s | 159 s | 42 s (4.8 + 36.3 + 0.9) |
| peak memory, wrap chain | 32–38 GB RSS (45–61 GB footprint) | 19.5 GB RSS (14.1 GB) | **10.6 GB footprint** (11.5 GB max RSS; 6.9 / 9.4 GB in a loaded run) |
| peak memory, IVC prove | — | 6.2 GB | 5.6 GB |
| bit-flip scan of the final proof | 0 accepted | 0 accepted (twice) | **513,736 flips, 512,943 decoded, 0 accepted** (956 s, after the review's length-binding fix) |

CPU per level (all threads, the run above): IVC 84 CPU-s (step 65,
decider 19); wrap 0 84, wrap 1 556, wrap 2 380 CPU-s. The 1/256 level's
commitments and its 24-bit grinding are the chain's largest cost.

What changed since §2:

- IVC grinding 16 bits per challenge (`ivc::SHIPPED_POW`; the step
  circuit fits 29,628 of 2^15 rows; `examples/ivc_plan` plans step size,
  rate and grinding without proving). Recursion ledger: every row ≥ 128,
  interactive weakest 111.34 (104.01 at 24 bits) — `soundness.md`
  § recursion.
- zerocheck prover: each line walked by additions; the first round in
  mixed base/Fp3 arithmetic (`air::mix`); the round's eq factor taken out
  (`h = L·q`, `q` at 8 points, 7 in the first round). Messages unchanged.
  The step's zerocheck went from 37 to 15.7 CPU-s.
- memory: key words always streamed; streamed trees keep no leaf level;
  streamed cosets as limb vectors written in place; `wrap_bench` holds
  two keys at a time.
- verifier: multi-openings expanded chain by chain in parallel;
  direct-opening folds in parallel (native interpreters only); parallel
  eq tables. With 4, 8 and 16 threads the warm verify is 2.80, 2.57 and
  2.52 ms: ≈ 2 ms of it is one thread's work (the transcript's 107
  single permutations ≈ 0.3 ms, decoding and the shared tree tops
  ≈ 0.45 ms, the pool's passes and the remaining serial arithmetic).
  Spinning pool workers were tried and made it slower (4.9 ms: they take
  cores from the verifying thread).

Still open: verify ≤ 1 ms (2.5 ms now, single-thread bound); the chain
in seconds (97 s quiet; the 1/256 level is ≈ 55 % of it — lowering its
rate needs ≈ 300 fewer rows in the final circuit, e.g. base-field key
words: the key's 12 Fp3 gate-coefficient columns make the key group's
leaf 11 permutations instead of 4); a 16 GB laptop is within reach
(10.6 GB footprint).

## 8. a hard size bound; the integrated stack (2026-10-13, `feat/proof-stack`)

- `wrap::max_proof_bytes` bounds the outermost proof over every
  transcript: all message shapes are the key's; a multi-opening of `q`
  leaves carries at most `Σ (a·n_{l+1} − n_l)` siblings, `n_l = min(q,
  nodes at level l)` (exact). Shipped chain: **65,177 B ≤ 65,536**, with
  no parameter change (a looser per-level bound gave 66,905 B and would
  have needed 27 grinding bits at the final level). The measured proofs
  (63,257–64,217 B) sit 1–2 KB under it.
- The envelope's `MAX_PROOF_BYTES` is `wrap::MAX_FINAL_BYTES`; the
  admitted final key is checked against it. The envelope itself adds its
  header, the chain and the statement (≈ 0.6–0.9 KB for small programs).
- Integrated with #57 (profile 6) and #59 (GPU backends): profile-6
  envelopes of hash.tri 64,003 B and tree-12 63,772 B; joy proves
  loop.tri wrapped in 75 s on Metal and 170 s on the CPU backend (keys
  derived in-process; load 12–50), peak 13.7 GB.

## 9. the size gate at 26 bits; inner keys over the base field (2026-10-13)

**Gate.** `wrap::max_proof_bytes(final key) ≤ 64 KiB`, hard, by key. At
the coordinator's decision the final level grinds 26 bits (`9f:26`): the
outermost proof is ≤ 64,213 B over every transcript, so a profile-6
envelope is ≤ 64 KiB whenever its encoded statement takes ≤ 1,272 B
(`specs/recursion.md` § size gate). Ledger: final weakest 128.43,
interactively 102.62 (`shift_2` after 26 query-grinding bits).

**Split key** (`feat/split-key`, stacked on #60). An inner level's key
columns with Fp3 entries (the four gates' `qa`, `qb`, `qc`: 12 of 108)
are committed as their three limbs, every column over the base field —
132 physical columns in three base words under one tree; the prover
sends the physical columns at `ρ`, the verifier rebuilds the logical
ones for `G` and batches the physical ones over 8 variables
(`recursion::splitkey`; ledger row `γ_k` 189.0). The key group's leaf
costs the next circuit 6 permutations instead of 11, so the final
circuit verifying a 1/128 second level fits 2^14 (16,230 of 16,384
rows; 15,236 at 1/256). Shipped chain `4i:16,7i:22,9f:26`; level 1
weakest 128.08, interactively 102.76 (its combination after 26 bits:
five words now). `WRAPPED_FORMAT` 5; `INNER_ROOTS`, `WRAPPED_DIGEST`
re-pinned.

Measured (machine shared, load 15–56; add.tri unless named):

| | `4i:16,8i:24,9f:24` (§8) | `4i:16,8i:24,9f:26` | `4i:16,7i:22,9f:26` (split key) |
|---|---|---|---|
| final proof bound | 65,177 B | 64,213 B | 64,213 B |
| final proof (this run) | 64,217 B | — | 62,965 B |
| envelope hash.tri / tree-12 | 64,003 / 63,772 B | 63,039 / 62,968 B | 63,103 / 63,448 B |
| verify 16T / 1T warm | 2.46–2.55 / 5.12–5.30 ms (quiet) | — | 3.03 / 5.24 ms (load ≈ 50) |
| prover chain keys (once per process), Metal / CPU | 30 / 61 s | 31 / 39 s | **11 / 16 s** |
| hash.tri profile-6 prove, Metal / CPU | 48.8 / 137.6 s | 95.6 / 169.8 s | **56.0 / 100.1 s** |
| tree-12 profile-6 prove, Metal / CPU | 80.2 / 139.6 s | 81.7 / 173.3 s | **60.2 / 124.4 s** |
| `joy prove loop.tri --succinct --wrap`, Metal / CPU | 75.2 / 170.1 s | 96.3 / 220.3 s | **61.0 / 151.1 s** |
| `joy verify` (keys cached) | 0.32 s | 0.30–0.39 s | 0.43 s |
| wrap chain CPU (wrap_bench, all threads): IVC · L0 · L1 · L2 | — | — | 98 · 104 · 475 · 724 CPU-s |
| peak memory (joy prove, Metal / CPU) | 13.7 / 12.9 GB | 13.3 / 12.8 GB | 14.6 / 13.2 GB |

Checks on the split-key branch: `cargo test --release -p zheng` all
suites green (297 lib); ignored `tests/wrapped_envelope.rs` 4/4, its
bit-flip sample 3,036 tried, 0 accepted; `tests/wrap_fastverify_review.rs
--ignored` on stored proofs green; `wrap_flip`: **503,720 flips,
502,921 decoded, 0 accepted** (567 s); joy e2e profile-6 test green.

**Cost found: the final level's fold grinding.** At a 26-bit budget
lens's schedule picks, per round, the regime with the fewest queries,
and for the final level's last round that regime needs 25-bit grinding
before each of its four folding challenges (at 24 bits: 22). The final
level's CPU rose from ≈ 380 to 724 CPU-s, ≈ 270 of them that grinding.
The size gate needs the 26 bits on the *queries* only (one query fewer
in the last round); a schedule with separate query and fold budgets
(26 / 22) would keep the bound and drop that cost — a lens schedule
option (`WhirConfig::derive` couples them today).

## 10. separate query and fold grinding budgets — evaluated, not adopted (2026-10-13)

lens `feat/whir-fold-budget` (8ec1f2b, on a3ce318): `WhirParams::fold_pow_bits`
(0: `pow_bits`; a version-2 header carries it), queries grinding
`pow_bits`, each round's regime chosen within the fold budget; lens's
39 rspcs tests pass with a test of the split schedule.

The size gate's last-round query saving (15 → 14) does not come from the
26 query bits: at rate 1/512, `ℓ = 20` the last round reaches 14 queries
only through the Johnson regime that grinds 25 bits before each of its
four folds; within a 22–24-bit fold budget it needs 15 at 26 query bits
and 14 only from 27. The final level's grinding (permutations per proof:
query grinds once per round, fold grinds once per folding challenge):

| query / fold budget | queries | fold grinding per round | grinding | proof bound |
|---|---|---|---|---|
| 24 / 24 (§8) | 24 / 18 / 15 | 17 / 20 / 22 | 3·2^24 + 4·(2^17+2^20+2^22) ≈ 72 M | 65,177 B |
| **26 / 26 (shipped)** | 24 / 18 / 14 | 17 / 20 / 25 | 3·2^26 + 4·(2^17+2^20+2^25) ≈ **340 M** | 64,213 B |
| 26 / 22 | 24 / 18 / 15 | 17 / 20 / 22 | ≈ 223 M | 65,177 B — misses the gate |
| 27 / 22 | 24 / 18 / 14 | 17 / 20 / 22 | 3·2^27 + 21.5 M ≈ 424 M | 64,213 B |
| 28 / 22 | 23 / 18 / 14 | 22 / 20 / 22 | ≈ 843 M | < 64,213 B |

Every configuration meeting the 64,213 B gate grinds at least as much as
the shipped one, so zheng keeps `9f:26` and the lens branch is not
merged into the stack. The lever left is a per-round query budget (24
bits in rounds 0 and 1, 27 in the last with 22-bit folds: ≈ 190 M, about
45 % less) — a further schedule option, not built.

## 11. the stack at merge time (2026-10-13, #61 on #60 on #58)

Measured 18:24–18:33 (1-minute load 5–20 except the verify runs, 51);
chain `4i:16,7i:22,9f:26`, IVC at 16 grinding bits; Metal and CPU give
the same bytes.

| | Metal | CPU (16 threads) |
|---|---|---|
| `joy prove loop.tri --succinct --wrap` (keys derived in-process) | **45.9 s**, 14.2 GB | **96.6 s**, 13.1 GB |
| profile-6 prove hash.tri / tree-12 (`wrapped_sizes`, keys derived first: 5.4 s / 12.5 s) | 36.8 / 41.7 s | 73.7 / 82.8 s |
| envelope hash.tri / tree-12 / loop.tri | 63,103 / 63,448 / 63,131 B | same |
| final proof (add.tri) / bound over every transcript | 62,965 B / **64,213 B** | |
| `joy verify loop.tri --proof` (keys cached) | 0.30–0.31 s per process | |
| verify, statement prepared, 16 threads warm / cold | 2.50 / 3.44 ms | |
| verify, one thread warm / cold | 5.14 / 6.14 ms | |

Against #56 (`audit/wrap-2026-10.md`): the wrap chain alone took 985 s;
now a whole profile-6 prove (IVC and wrap chain) of hash.tri takes 36.8 s
on Metal and 73.7 s on the CPU (the joy prove of loop.tri, keys included,
46 s),
peak memory from 32–38 GB to 14.2 GB, verify from 6.4–7.2 ms to 2.5 ms
on 16 threads (10.1–10.9 → 5.1 ms on one), the proof bounded by
construction at 64,213 B. Checks: zheng suites green on #61, the bit-flip
scan (503,720 flips, 0 accepted) and the ignored envelope tests (bit-flip
sample 0 accepted) on #61's code; joy's 34 suites and the end-to-end
profile-6 test green on it. joy wraps by default from 16 GiB available
(the 14.6 GB peak plus 15 %).

Open: verify ≤ 1 ms (≈ 2 ms of single-thread work); the final level's
grinding (a per-round query budget, §10).
