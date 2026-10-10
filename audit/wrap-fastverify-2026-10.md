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
| bit-flip scan of the final proof | 500,712 flips, 0 accepted | **510,920 flips, 510,104 decoded, 0 accepted**, 0 panics (562 s) | 0 — met |

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
| final 1/512, grinding 24, `n = 14`, `ℓ = 20` | 15,606 → 2^14 | 24 / 18 / 15 | fold_1 128.40 | 104.70 |

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
| bit-flip scan (`wrap_flip add.tri`) | 510,920 flips, 0 accepted |
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
