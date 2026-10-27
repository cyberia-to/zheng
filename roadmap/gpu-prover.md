---
tags: cyber, cip
crystal-type: process
crystal-domain: cyber
status: draft
---
# GPU-native full-stack prover

a single GPU pipeline that takes a nox trace and produces a zheng proof without returning to the CPU between proving phases. this page proposes the step beyond what ships; the part that ships is stated first.

## what exists (master, 2026-10-27)

the prover backends of phase P of the [[soft3/proposals/proof-system-repair|proof-system repair]] exist: one backend trait at [[lens]] (hemera permutations, grinding, coset NTT, Merkle levels), a Metal backend through [[honeycrisp]] on Apple Silicon and a WebGPU backend through wgpu (crate `cyber-lens-gpu`), the CPU as the fallback. zheng picks one with `ZHENG_BACKEND=cpu|metal|webgpu|auto` in its examples and benches. every backend produces the same proof bytes (SHA-1 equal per fixture), and verifiers make no backend calls (`audit/proof-stack-review-2026-10.md`).

measured on an Apple M4 Max, machine shared with other agents:

- profile 1, `hash.tri` through `joy prove --succinct`: 17.7 s CPU-bound grinding → 1.4 s on Metal after the backends (`audit/prover-profile-2026-10.md`), then 41 ms prove / 0.07 s wall in a fresh process after the fast path's parameters and kernels (soft3 `audit/proof-latency-2026-10.md` §3);
- profile 5, one IVC step of 2^15 rows: 1.12–1.15 s on Metal, 2.34–2.39 s WebGPU, 2.65–2.70 s CPU; profile 6, the wrap chain: 18.9 s Metal, 49.4 s WebGPU, 59.8 s CPU (`audit/ivc-speed-2-2026-10.md`).

these figures were taken on hemera 0.3.1, which the crate still pins; the frozen hemera 0.4 (more rounds) moves them, and the sweep is zheng#69/#73.

what does not exist: a pipeline that stays on the device from trace to proof. constraint evaluation in the zerocheck and the Spartan sumchecks run on the CPU in every backend; the device does hemera, grinding, NTTs and trees, with transfers between phases (on Apple Silicon these are unified-memory hand-offs, not PCIe copies).

## the gap this page proposes to close

```
today:   trace (CPU) → commit (device) → sumcheck / zerocheck (CPU) → open (device) → proof
```

on a discrete GPU each hand-off is a PCIe transfer of tens of microseconds plus bandwidth; for small proofs the transfers and dispatches, not the arithmetic, set the floor.

## target pipeline

```
GPU:     trace → commit → sumcheck → open → proof
         all in VRAM, zero PCIe transfers

proof latency: dominated by computation, not transfer
```

## components

### nebu GPU kernels

field arithmetic over Goldilocks as WGSL compute shaders:

```
add(a, b):     one u64 add + conditional subtract     (~1 GPU cycle)
mul(a, b):     one u64×u64 → u128 + sparse reduce     (~4 GPU cycles)
ntt(data, n):  Cooley-Tukey butterflies                (~n/2 × log(n) × 4 cycles)
batch_inv(v):  Montgomery trick on GPU                 (1 inv + 3(N-1) muls)
```

NTT is embarrassingly parallel — each butterfly is independent within a stage. GPU occupancy is near-100% for N ≥ 2¹⁶.

### hemera GPU kernels

hemera's permutation, Merkle levels and grinding already run on Metal and WebGPU (lens `cyber-lens-gpu`). what remains for a device-resident pipeline:

```
tree_commit(leaves):   parallel leaf hashing + tree reduction
                       2^20 permutations: 19.7 ms Metal, 83.8 ms WebGPU (M4 Max, audit/ivc-speed-2-2026-10.md)

fiat_shamir(transcript): sequential sponge (hard to parallelize)
                         but transcript is short — negligible cost
```

### zheng GPU prover

the full pipeline in VRAM:

```
PHASE 1 — COMMIT:
  polynomial evaluations already in VRAM (from nox trace)
  NTT for RS encoding: O(N log N) nebu muls → GPU-parallel
  hemera Merkle tree over the codeword: GPU-parallel

PHASE 2 — SUMCHECK:
  k = log(N) rounds
  each round: evaluate degree-d polynomial at d+1 points
  = sparse matrix-vector multiply over VRAM trace
  GPU-parallel per evaluation point

PHASE 3 — OPEN:
  WHIR folding: fold k = 4 variables per round + hemera tree per round
  GPU-parallel

OUTPUT:
  proof copied to CPU (one small transfer; tens of KB — profile 1
  measures 16,756 B for one hemera hash and ≤ 64 KB up to 2^18
  committed variables, soft3 audit/proof-latency-2026-10.md)
```

## expected performance

no discrete-GPU (NVIDIA, AMD) figure has been measured. the earlier table of A100 / RTX 4090 estimates was never run and is removed; the measured Apple Silicon figures are in the first section. multi-GPU: NTT and tree construction partition by data segment and sumcheck by evaluation point, to be measured.

## foculus π computation on GPU

the same GPU running proofs also computes foculus π iteration:

```
SpMV (sparse matrix-vector multiply):
  estimate, not measured: ~50M edges at 40 Hz = 2×10⁹ edge ops/s on a datacenter GPU

combined pipeline:
  1. receive new signals → update sparse matrix (CPU)
  2. SpMV iteration (GPU) → update π estimate
  3. finalize particles above τ (CPU)
  4. prove finalized state transitions (GPU) → proofs

single GPU handles BOTH consensus computation AND proving
```

## WGSL portability

hemera's GPU backend uses WGSL (WebGPU Shading Language) — runs on any GPU with WebGPU support (Vulkan, Metal, DX12). not CUDA-locked. the same shaders work on:
- NVIDIA (datacenter and consumer)
- AMD (RDNA)
- Apple (M-series via Metal)
- Intel (Arc)

nebu and zheng GPU kernels should follow the same WGSL approach for portability.

## relation to other proposals

- lens: WHIR won the phase-2 bake-off and ships, so the GPU prover is NTT- and hemera-heavy (Reed–Solomon encoding, Merkle trees). the expander-code (Brakedown) lens is retired; no SpMV-heavy commitment path remains
- accumulation (phase 3): long computations are proven step by step, each step batching claims with a sumcheck, committing one combined word and opening a few positions. each step is itself an NTT + Merkle workload, so the GPU pipeline becomes a streaming one; whether GPU or CPU wins per step is to be measured
- Binius lens (research, not in the stack): binary operations are 128× more data-parallel on GPU (128 F₂ elements per word). binary proving on GPU is extremely efficient — the packing advantage multiplies the GPU parallelism advantage

## open questions

1. Fiat–Shamir sequentiality: hemera sponge is sequential (each squeeze depends on previous absorb). transcript processing cannot be parallelized. for short transcripts (~100 absorptions) this is negligible. for long interactive proofs, it may bottleneck
2. VRAM capacity: 2³⁰ trace = 16 GB fills consumer GPU. tensor trace compression ([[tensor]]) reduces memory to O(√N), enabling large traces on consumer hardware
3. kernel launch overhead: a compute dispatch costs microseconds. minimize dispatch count by fusing pipeline stages into larger kernels
4. mixed precision: GPU hardware has fast f16/f32 paths. Goldilocks is u64. no hardware acceleration for 64-bit field arithmetic on current GPUs. future GPU architectures (or GFP custom silicon) would change this

see [[soft3/proposals/proof-system-repair|proof-system repair]] §5 phase P for the gate, lens `specs/backend.md` for the backend contract, and [[accumulation]] for the step workload