---
tags: zheng, audit, prover, gpu, metal, webgpu, profile
crystal-type: audit
crystal-domain: crypto
---
# prover profile and backends — 2026-10-10

Owner directive (2026-10-10): proving runs on any device through joy —
Metal through honeycrisp on Apple Silicon, WebGPU through wgpu elsewhere,
CPU as the fallback — and takes seconds, never minutes. Goal row: soft3
`proposals/proof-system-repair.md` §0 and phase P (soft3#173). Contract of
the backends: lens `specs/backend.md`.

Stand: zheng `feat/gpu-backend` — first on `feat/wrap-envelope` (#57,
cede6bd: profiles 1 and 5 below, tables A–B), then rebased onto
`feat/wrap-fastverify` (#58, 379eda2: the streaming commitment and the
`4i:16,8i,9f:24` chain; the wrap chain, table C); lens `feat/gpu-backend`
(lens#23, on `feat/field-native-whir`, #21); joy `feat/gpu-backend` (joy#40,
on `feat/wrap`, #39); honeycrisp `main` 9cbd480 (aruminium); strata `main`
494df7a. Baseline = the same fixtures built from the base commits (zheng
cede6bd, lens c91f55a, joy a6eedee) — or, for the wrap chain, #58's own
CPU path (`ZHENG_BACKEND=cpu` on this branch runs #58's code with lens's
CPU backend at the seams). Apple M4 Max,
16 cores (12P + 4E), 40-core GPU, 48 GB, macOS 26.4, rustc 1.95.0,
`--release`. **The machine was shared with other agents through every run:
load average 20–78, other proofs resident (10–21 GB), and the GPU 62 %
busy with another client when idle-checked (`ioreg` Device Utilization).**
Wall times are single runs under that load — upper bounds of a quiet
machine, noisy by ±50 %; CPU seconds (`user`) are the steadier figure.
Sizes and proof bytes are deterministic.

## 1. where prove time goes (before the backends)

Method: macOS `sample` (1 ms) over the whole prove, inclusive samples per
worker spawn site (thread samples, so CPU-milliseconds), plus
`ZHENG_TIMING` laps for wall time.

### profile 1 (succinct), hash.tri — `joy prove --succinct`

17.7 s wall, 150 CPU-s, 38 MB. **100 % of the sampled prove is
`lens::rspcs::pow::grind`** (WHIR grinding, 24 bits per round, ≈ 3.6 × 2²⁴
hemera hashes, one `hemera::hash(seed ‖ nonce)` call per nonce, no
batching). Relation, witness, commit, Spartan and the opening together take
≈ 45 ms (`audit/succinct-profile-2026-10.md`).

### profile 5 (IVC), hash.tri — one 2¹⁵-row step, rate 1/16, pow 24

`ivc_bench hash.tri`: 32.7 s prove (load 17–20), 200 CPU-s, 6.2 GB.

| phase (wall, `ZHENG_TIMING`) | s |
|---|---|
| pre-commit (nox phase 1 word) | 1.1 |
| step: word b + word c commits | 2.2 |
| step: zerocheck | 3.6 |
| step: folds + shift | 0.2 |
| step: accumulation — sumcheck (serial eq tables, rounds, folds) | 4.4 |
| step: accumulation — commit, OOD, two grinds | 4.9 |
| decide (one batched WHIR opening) | 15.2 |

| operation class (CPU) | CPU-s | share |
|---|---|---|
| hemera: grinding (`sponge::grind`) | 37.8 | 17 % |
| hemera: Merkle leaf sponges (base + ext words) | 55.5 | 25 % |
| hemera: Merkle nodes | 18.5 | 8 % |
| zerocheck: relation evaluation over Fp3 (`Relation::eval`, `CircuitAir`) | 60.8 | 27 % |
| RS encoding (nebu NTT per coset) | 21.6 | 10 % |
| main thread, serial (sumcheck tables, folds, Horner, combinations) | 14 | 6 % |

Hemera — grinding and Merkle trees — is half the CPU; Fp3 constraint
evaluation a quarter; the serial main thread decides the wall time of the
accumulation sumcheck and the decider.

### profile 6 (wrap chain)

Before #58 (`audit/wrap-2026-10.md` §2–3, CPU): add.tri IVC 26.8 s, wrap
levels 84.5 / 168.4 / 731.9 s, 32–38 GB peak; the final level's opening
dominated (grinding 30 bits per round, 2³⁰ permutations a round). #58
(`audit/wrap-fastverify-2026-10.md`) cut the chain to 83 s and 19.5 GB
(streamed codewords, key words committed once, chain `4i:16,8i,9f:24`:
grinding 24 bits at most); its remaining time is ≈ 70 % commitment hashing
(coset NTT + leaf sponges of the streamed words) and ≈ 20 % grinding — the
two operations the backends take (§4 C). In the CPU run of table C (load
67–77) the batched permutation counter reads 1.15 × 10⁹ hemera
permutations for IVC + chain.

## 2. what was built

| piece | where |
|---|---|
| `Backend` trait: `permute` (hemera, many states), `grind` (least nonce, two nonce injections), `sponge` (overwrite sponge per item: Merkle leaves), `coset_ntt`; `Cpu`; process-wide `current`/`install` | lens `rspcs/src/backend.rs`, spec `specs/backend.md` |
| Metal backend: MSL kernels (native 64-bit, constants inlined), shared-storage (unified memory) buffers, honeycrisp aruminium | lens `gpu/src/{metal,msl}.rs` |
| WebGPU backend: WGSL kernels over 32-bit limbs, ≤ 2 storage buffers per kernel (PowerVR), wgpu 28; builds for wasm32 and Android | lens `gpu/src/{webgpu,wgsl}.rs` |
| call sites: lens WHIR/TensorRs grinding, RS encoding; zheng `permute_many` (batches ≥ 4096), recursion grinding, leaf sponges of held words (one call per tree), streamed words (`stream::digests_grouped`: coset groups of ≥ 2¹⁶ leaves, CPU encoding pipelined with device hashing) | lens `pow.rs`, `rs.rs`; zheng `recursion/{perm,sponge,word,stream}.rs` |
| CPU: grinding claims batches until the least nonce (was: 16 threads spawned per 64K nonces); threaded eq tables, scaled-eq sums, folds, ML and univariate evaluation; threaded WHIR word combinations (the accumulation sumcheck's threading of the first stack is #58's own now) | lens `backend.rs`, `field.rs`; zheng `recursion/whir/prove.rs` |
| `joy prove --backend auto\|cpu\|metal\|webgpu` (`JOY_BACKEND`), backend reported | joy `cli/prove.rs` |
| `ZHENG_BACKEND` in the benches | zheng `tests/common/mod.rs` |

### backend coverage

| operation | cpu | metal | webgpu |
|---|---|---|---|
| hemera permutation batch (Merkle nodes, sponge blocks) | ✓ | ✓ (≥ 4096 states) | ✓ (≥ 4096 states) |
| leaf sponges, whole batch in one call (held and streamed words) | ✓ | ✓ | ✓ |
| grinding, field-native lane (recursion) | ✓ | ✓ | ✓ |
| grinding, `hemera::hash(seed ‖ nonce)` (lens WHIR) | ✓ | ✓ | ✓ |
| coset NTT (lens RS encoding) | ✓ | ✓ (≥ 2¹², parity with cpu) | — (cpu) |
| coset NTT of streamed words (zheng `stream.rs`) | ✓ | — (cpu, pipelined with the device sponge) | — (cpu, pipelined) |
| lens byte-hash Merkle trees (profiles 1/4) | ✓ | — (cpu) | — (cpu) |
| sumcheck rounds, folds, eq tables, ML/univariate evaluation | ✓ threaded | — (cpu) | — (cpu) |
| zerocheck constraint evaluation (Fp3 relation) | ✓ threaded | — (cpu) | — (cpu) |

## 3. same bytes on every backend

- `gpu/tests/differential.rs` (lens): permutations of random states with
  zero and `p − 1` lanes (4096, 5000, 70,001 states; all-zero states),
  grinding for 1–18 and 20 bits with both injections (nonces beyond the
  first dispatch), Metal with 2–4 states per thread sharing inversions,
  coset NTTs 2¹²–2¹⁶ — Metal and WebGPU equal to CPU; 6 tests,
  `LENS_GPU_REQUIRE=metal,webgpu` green.
- envelopes (`envelope_profiles`, `ZHENG_ENVELOPE_DIR`): SHA-1 equal across
  baseline, cpu, metal, webgpu — hash.tri p1 `31ebd6ff…`, hash.tri p5
  `049777ae…`, merkle-32 p5 `416e4dc6…`, tree-12 p5 `79f89ba5…`
  (baseline, metal, webgpu; the cpu tree-12 run was cut by a time limit).
- joy artifacts: `joy prove --succinct hash.tri` baseline / cpu / metal /
  webgpu all `a3cb76d2…` (16,308 B); `joy verify` accepts each.
- wrap chain (#58 stack): IVC proof, wrap 0, wrap 1, wrap 2 and the final
  proof stored by `wrap_bench` — SHA-1 equal on cpu and metal in two
  independent pairs of runs (final `67d5ab70…`, 62,544 B).
- `recursion::word::tests::device_paths_give_the_cpu_digests`: the device
  paths (one sponge call per batch, coset groups) through a renamed CPU
  backend give the CPU digests, held and streamed, base and Fp3.
- zheng `cargo test --release`: 332 passed, 0 failed, 12 ignored on the
  pre-#58 stack (transcript_pin, recursion, recursive_envelope, wrap,
  wrap_review included); on the #58 stack (379eda2): 330 passed, 0 failed, 7 ignored; on 5d7c959: 331 passed, 0 failed, 7 ignored; lens rspcs 37
  passed; joy 228 passed, 0 failed.

## 4. timings

All runs on the machine described above; load average at the start of
each block in brackets. Proof bytes are identical in every column (§3).

### A. profile 1 (succinct), hash.tri

`joy prove --succinct hash.tri --input-values 7` (whole CLI, one run each,
load 30–49):

| backend | prove | peak RSS |
|---|---|---|
| baseline (before the backends) | 17.7 s | 38 MB |
| cpu | 5.5 s | 53 MB |
| metal | 1.36 s | 52 MB |
| webgpu (wgpu on Metal) | 2.8 s | 56 MB |

zheng library (`envelope_profiles`, prove only, two interleaved rounds,
load 57–93): baseline 16.5 / 7.7 s · cpu 1.9 / 2.4 s · **metal 0.4 /
0.4 s** · webgpu 0.6 / 0.7 s.

### B. profile 5 (IVC), pre-#58 stack

`envelope_profiles hash.tri tree-12` (`ZHENG_PROFILES=1,5`), two
interleaved rounds (load 57–93):

| fixture | baseline | cpu | metal | webgpu |
|---|---|---|---|---|
| hash.tri (1 step of 2¹⁵ rows) | 82.0 / 55.9 s | 36.2 / 42.2 s | **19.4 / 24.2 s** | 27.9 / 29.4 s |
| tree-12 (2 steps) | 76.7 / 75.0 s | 63.6 / 70.7 s | **28.6 / 29.9 s** | 40.6 / 28.9 s |
| process CPU time (p1 + p5 × 2 fixtures) | 584 / 577 s | 508 / 510 s | **110 / 112 s** | 150 / 158 s |

Memory: 6.2–7.8 GB peak on every backend (the IVC's tables; the backends
add the batch staging buffers only).

### C. wrap chain (profile 6), #58 stack

`wrap_bench add.tri` (IVC proved, then the three levels; fresh
`ZHENG_IVC_DIR` per run), the two runs back to back (16:40–16:47, load
67–95):

| | cpu (#58's path) | metal |
|---|---|---|
| IVC prove | 28.7 s | 21.2 s |
| wrap 0 / 1 / 2 prove | 13.1 / 65.4 / 51.0 s | 17.3 / 55.6 / 39.7 s |
| wrap chain | 129.5 s | **112.5 s** |
| key derivation (once per chain) | 2.0 + 6.7 + 46.7 + 1.9 s | 1.2 + 4.4 + 34.8 + 1.6 s |
| whole process | 215.9 s wall, **1,755 CPU-s** | 176.2 s wall, **192 CPU-s** |
| peak RSS | 9.4 GB | 10.8 GB |
| final proof | 62,544 B | 62,544 B, same bytes |

Inside the levels (metal vs cpu, same runs): grinding at 24 bits fell from
0.4–4.2 s to 0.1–1.2 s a round; the streamed commitments did not get
faster (wrap 1 words 17.3 vs 18.4 s; round commits 10.4 / 6.4 / 12.5 vs
15.5 / 9.4 / 4.9 s) — the first device path built every coset group on one
thread and then hashed it. A pipelined version (the CPU encodes the next
coset group while the device hashes the current one; commit
"device streaming pipelined") ran once at 16:50 under a heavier load (key
derivation alone 2.9× slower than in the pair above): chain 29.7 / 54.8 /
31.2 s, process 332 CPU-s — not comparable to the pair; a quiet-machine
pair is open.

Peers, for scale: #58's own run (`audit/wrap-fastverify-2026-10.md`, load
24–41): wrap 11.8 / 42.5 / 28.7 s = 83.0 s.

### C′. wrap chain on #58 at 5d7c959 (lean streaming, IVC grinding 16 bits)

The same pair after rebasing onto #58's later head (2026-10-13 14:13–14:23,
load 40 → 156: the CPU run's second half ran at a load of 110–156, so its
level times are inflated; CPU seconds are the steadier comparison):

| | cpu (#58's path) | metal |
|---|---|---|
| IVC prove | 22.6 s | **9.6 s** |
| wrap 0 / 1 / 2 prove | 26.6 / 126.3 / 86.2 s | 30.5 / 55.2 / 29.8 s |
| wrap chain | 239.1 s | **115.5 s** |
| key derivation (once per chain) | 2.3 + 7.7 + 57.4 + 1.3 s | 2.1 + 12.7 + 109.8 + 2.6 s |
| whole process | 330.7 s wall, **1,771 CPU-s** | 253.1 s wall, **330 CPU-s** |
| peak RSS | 7.3 GB | 10.0 GB |
| proofs (IVC, wrap 0–2, final) | — | SHA-1 equal to cpu (final `d9feb171…`) |

The 1/256 level's key derivation (its key words always streamed now, Fp3
over 2²⁹ points) ran slower through the device path than on 16 cores in
this pair (110 vs 57 s): the CPU still runs every coset NTT there and the
lanes cross into the device buffer by a copy; open (§5, item 2).

### D. kernels (`cyber-lens-gpu` `gpu_bench`)

| backend | hemera permutations | grind 24 bits (62.0 M nonces) | grind 30 bits (1.08 G nonces) | coset NTT 16 × 2²⁰ |
|---|---|---|---|---|
| cpu, 16 threads | 7–12 M/s | 5.1–11.6 s | 143.0 s | 83–173 ms |
| metal | 27–39 M/s | 1.4–1.9 s | **27.3 s** | 63–107 ms |
| webgpu (on Metal) | 7–15 M/s | 3.1–3.6 s | 41.4 s | (cpu) |

The GPU was shared (62 % utilised by another client when sampled), so the
Metal figures are lower bounds of the device. Tried and kept off: 2–8
states per thread sharing the partial-round inversion (no gain: register
pressure), threadgroup sizes 32–1024, full loop unrolling, `mulhi` vs
explicit 32-bit limb products — all within noise of each other.

## 5. what reaches seconds, what does not

| profile | today (best backend, this machine, loaded) | seconds? |
|---|---|---|
| 1 (one relation ≤ 2¹⁵ rows) | 0.4 s library, 1.4 s CLI on Metal; 0.6 s WebGPU; 1.9–2.4 s CPU | **yes** — every backend |
| 5 (IVC), per 2¹⁵-row step | 9.6 s Metal on #58's head (19–24 s on the pre-#58 stack), 22–42 s CPU | close — single-digit seconds per step on Metal, tens on CPU |
| 6 (wrap chain) | 112–116 s Metal; 130–239 s CPU under load (#58 alone: 83 s on a quieter machine) | no — about two minutes |

What still costs time, from the profiles above:

1. **Constraint evaluation in the zerocheck** (IVC step: `Relation::eval`
   over Fp3, ≈ 50 % of the remaining CPU; the wrap levels' `zerocheck` laps,
   5–9 s each) — generic Rust over `air::num`; it runs on the CPU in every
   backend. A device kernel needs the constraint graph compiled to MSL/WGSL
   (`air::num::Graph` already records it; #58 compiles it for the
   verifier), evaluated per row on the device.
2. **Streamed commitments** — coset NTTs and leaf sponges of words of
   2²⁵–2²⁹ symbols. On a device the sponge is fast; the coset NTT stays on
   the CPU (the Metal NTT, one radix-2 stage per dispatch, is at parity with
   16 cores) and the lanes are laid out by the CPU and copied into the
   device buffer. Next: a fused NTT-in-threadgroup-memory kernel feeding the
   sponge kernel directly from device memory (no lane copies: the codeword
   never leaves the GPU, unimem's zero-copy rule), and pipelining measured
   on a quiet machine.
3. **Serial main-thread work** — transcripts, openings, the round loop of
   WHIR (`this thread's CPU` 2–8 s a level).
4. **Algorithmic size** (agent V / #58): key derivation of the 1/256 level
   (35–47 s, once per chain — cached keys remove it from proving), the
   1/256 and 1/512 codewords themselves, and the IVC step's two words of
   2²¹ cells.

Browser and phones: the backends build for wasm32-unknown-unknown and
aarch64-linux-android; a browser cannot block on GPU readback, so the
synchronous prover there needs an asynchronous backend; zheng itself does
not build for wasm32 yet (64-bit `usize` arithmetic in `recursion/ivc.rs`,
getrandom without `wasm_js`), and the IVC's 6–8 GB exceed wasm32's 4 GB.
