---
tags: zheng, lens, audit, recursion, gpu, performance
crystal-type: audit
crystal-domain: crypto
---
# IVC step and wrap chain speed, round 2 — 2026-10-14

superseded by hemera 0.4 (2026-10-16): the hemera figures below (x⁻¹ partial rounds, 8 + 16 rounds, 144 constants, ~736 constraints) describe the 0.3 record; the frozen profile is x⁷ in every round, 6 + 6 + 48 rounds, 240 constants, ~1,440 constraints — `hemera/audit/profile-0.4-2026-10.md`.

Follow-up to `audit/ivc-speed-2026-10.md` (zheng #63, lens #24). Items
from the coordinator: (1) the hemera device kernels — batched partial
inversions, tuned arithmetic — on Metal, WebGPU and the CPU path, target
≥ 3× on the wrap chain; (2) a compiled device program for the zerocheck
line sums; (3) prover keys from disk; (4) the step's serial CPU
overlapped with device work. Branches: lens `feat/kernel-speed` off
`release/0.2` (61c2a8f), zheng `feat/ivc-speed-2` off `release/0.4`
(15b9549). Same machine and stand as round 1; the machine was shared
with the fast-path agent's runs during the session — the tables below
are runs taken when its jobs were idle (1-minute load 5–7 at the start).
Every change is prover-only: no transcript, shape, key or pin changes.

## 1. results

| | Metal (round 1 → **round 2**) | WebGPU | CPU |
|---|---|---|---|
| hemera grind, 24 bits (62 M nonces; `gpu_bench`) | 1,301 → **905 ms** (1.44×) | 2,084 → **1,294 ms** (1.61×) | 4,659 ms (unchanged) |
| hemera permute 2^20 (with copies) | 26.6 → 19.7 ms | 79.5 → 83.8 ms | 81.9 ms |
| IVC step, hash.tri | 1.19 → **1.12–1.15 s** | 2.29 → 2.34–2.39 s | 2.79 → 2.65–2.70 s |
| IVC prove (step + decider) | 1.88 → **1.77–1.79 s** | 3.25 → 3.28–3.32 s | 3.73 → 3.61–3.66 s |
| wrap 0 / 1 / 2 | 3.60 / 7.63 / 12.47 → **3.31 / 6.31 / 9.24 s** | 6.30 / 24.01 / 27.01 → 6.51 / 17.47 / 25.41 s | 7.24 / 19.19 / 36.11 → 7.63 / 18.86 / 33.28 s |
| **wrap chain** | 23.7 → **18.9 s** | 57.3 → **49.4 s** | 62.5 → 59.8 s |
| key derivation, IVC + 3 levels | 0.3 + 0.9 + 3.2 + 0.2 → **0.10 + 0.15 + 0.11 + 0.19 s** (cache warm) | 0.10 + 0.15 + 0.10 + 0.20 s | 0.11 + 0.16 + 0.13 + 0.15 s |
| whole profile-6 process (keys + IVC + chain + verifies) | 31.0 → **21.9 s** | 71.5 → 53.5 s | 79.5 → 65.1 s |
| peak RSS | 10.5 → 11.2 GB | 13.4 → 12.0 GB | 11.4 GB |

Same bytes: hash.tri IVC `59bfc9c5…`, add.tri IVC `01cfef5e…`, final
`7580817e…` — SHA-1 equal on Metal, WebGPU and CPU, and equal to round
1's (`audit/ivc-speed-2026-10.md` §1).

## 2. what was done

| item | change | result |
|---|---|---|
| 1 Metal | hemera's CPU kernel structure in MSL: representatives below 2^64 between operations (one reduction a product), wide sums reduced once (external layer, `Σ_{i≥1} s_i`), fused multiply-adds, the partial rounds' next S-box input carried as `(d₀+1)·y + (Σ + c)`; **four states a thread, one inversion a partial round** (Montgomery's trick, zero ↦ zero by masks); the sponge, coset-leaves and Merkle kernels take four items a thread (`gid + k·T`, coalesced) | compute 1.44×; coset leaves in the step 660 → 463 ms |
| 1 WebGPU | **two states a thread, one inversion a partial round** in the permute, grind, sponge and Merkle kernels | grind 1.61× (an inversion is ~16 limb products of 16 bits per multiplication in WGSL); the coset-leaves kernel stays single (paired it read slower: its cost is the values' readback) |
| 1 CPU | already in hemera `main` (#17): 16-lane batches, Montgomery's batch inversion across lanes, aarch64 multiply-reduce in assembly, the partial-round chain interleaved | nothing to add |
| 2 | compiled line-sum kernels from the recorded program (straight-line MSL, then blocks of 256 operations as functions with live values through a private array) | **rejected**: the 12,307-operation program compiled in 384 s and ran 2.5× slower than the interpreter (275 vs 107 ms round 0); the inline form did not finish compiling in 10 min. A wide-accumulating Fp3 product in the interpreter did not move it either (107 vs 105 ms): the interpreter is bound by its register traffic, not its arithmetic. Kept: the interpreter |
| 3 | committed key trees on disk (`ZHENG_KEY_CACHE=<dir>`, `recursion::keycache`): stored under a 128-bit digest of the members' coefficients, layout and fan-in; a damaged or foreign file ignored; roots still checked against the pins | chain keys 4.8 → 0.55 s; IVC key 0.25 → 0.10 s |
| 4 | the zerocheck's columns (local, successor, public, key, public input) assembled and packed for the device on other threads while word c commits on the device | step −30–40 ms |

### why ≥ 3× on the chain is out of reach with the kernel alone

Cross-thread batching does not pay on a GPU: a SIMD group runs one
instruction stream, so one inversion shared by 32 lanes costs those lanes
the same 72 multiplications as 32 private inversions — the saving needs
several states *per thread*. Measured: states in threadgroup memory (4 a
thread) ran 1.8× slower than registers (the state traffic); four states
in registers with the old arithmetic gained 13 % (register pressure);
removing the inversions entirely (not hemera) gained 1.5× — the ceiling
of any inversion trick. With the lazy arithmetic and four states a thread
the Metal kernel is 1.44× on pure compute; the chain gained 1.25× (its
coset-leaves and Merkle dispatches move memory as well as hash).

## 3. review

Prover-only changes (no transcript, key, shape or ledger change); the
evidence is byte identity and the differential tests:

| check | result |
|---|---|
| lens differential (`LENS_GPU_REQUIRE=metal,webgpu`): permutations (random, zero and `p − 1` lanes, all-zero states), grinding across dispatches, sponges, coset leaves (kept and ragged groups), Merkle levels, line sums and sessions | 14/14 |
| new: states built backwards through the first four full rounds so the first partial S-box input is zero, at every position of a batch (Metal: four a thread; WebGPU: pairs) | equal to the CPU on both devices |
| new: line sums over runs of edge limbs (`p − 1`, `p − 2^32`, 0, 1) | equal |
| proofs: IVC (hash.tri, add.tri) and the add.tri chain's final proof on Metal / WebGPU / CPU | SHA-1 equal, and equal to round 1's |
| key cache: a stored tree loads as the committed one (binary and 4-ary), another key's members never hit it, a truncated file is ignored and recommitted | `recursion::word::tests::a_cached_key_tree_is_the_committed_one` |
| zheng workspace | see §4 |

## 4. runs

| run | result |
|---|---|
| zheng `cargo test --release --workspace` | 368 passed, 0 failed, 17 ignored |
| zheng `wrapped_envelope --ignored` (fresh profile-6 prove on Metal, inner roots checked, bit-flip sample) | 4 passed |
| joy `release/0.4` `wrapped_execution --ignored` (e2e profile 6) over this zheng and lens | passed |

## 5. what is left

- **IVC step 1.12 s on Metal** (≤ 1 s missed by ~0.12 s). Device ≈ 0.6 s
  now; the zerocheck interpreter (≈ 0.23 s) and the serial CPU (circuit
  build 72 ms, the accumulation's eq tables ≈ 120 ms) are the rest.
  Next: specialised zerocheck kernels per constraint kind instead of one
  interpreted program (compiled whole programs are not viable on the
  Metal compiler), the accumulation sumcheck's first round started
  before `γ` (the accumulator's claims are known at the step's start).
- **Wrap chain 18.9 s on Metal** (≤ 5 s missed by ~4×). Still ≈ 0.9 G
  hemera permutations, now at ≈ 55–70 M/s; the final level ≈ 9 s. The
  remaining levers are structural (a smaller final circuit or a cheaper
  final-level commitment) — no kernel-only path reaches 3×.
- WebGPU: the kept-codeword readback dominates its commitments (coset
  leaves 1.6–1.8 s in the step); a device-resident codeword would remove it.
