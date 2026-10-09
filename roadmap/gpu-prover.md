---
tags: cyber, cip
crystal-type: process
crystal-domain: cyber
status: draft
---
# GPU-native full-stack prover

a single GPU pipeline that takes a nox trace and produces a zheng proof without returning to CPU. eliminates PCIe round-trips between proving phases. targets 100-1000× throughput on commodity hardware.

## current pipeline

```
CPU:     trace → [PCIe] → GPU commit → [PCIe] → CPU sumcheck → [PCIe] → GPU open → [PCIe] → proof
         ~~~~~            ~~~~~~~~~~             ~~~~~~~~~~~             ~~~~~~~~~~
         slow             fast                   slow                    fast

each PCIe transfer: ~10-50 μs latency + bandwidth-limited
4 round-trips per proof: ~40-200 μs overhead
for small proofs: PCIe dominates proving time
```

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

hemera already has WGSL backend (28 shaders). extend to batched proving operations:

```
tree_commit(leaves):   parallel leaf hashing + tree reduction
                       2^20 leaves: ~2 ms on A100

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
  proof copied to CPU (one small PCIe transfer; tens of KB —
  15,921 B measured for one hemera hash, 71,081 B for a 2^20 relation)
```

## concrete performance

### single GPU (A100, 80 GB VRAM)

| operation | CPU (single core) | GPU (A100) | speedup |
|---|---|---|---|
| NTT 2²⁰ | ~50 ms | ~1 ms | 50× |
| hemera tree 2²⁰ leaves | ~100 ms | ~2 ms | 50× |
| sumcheck 20 rounds | ~200 ms | ~5 ms | 40× |
| WHIR open | ~150 ms | ~3 ms | 50× |
| **full proof** | **~500 ms** | **~11 ms** | **~45×** |

### consumer GPU (RTX 4090, 24 GB VRAM)

~3× slower than A100 for field arithmetic. full proof: ~30-50 ms. still real-time for block times > 1s.

### multi-GPU

NTT and tree construction partition across GPUs by data segment. sumcheck parallelizes across evaluation points. linear scaling up to 4-8 GPUs before communication overhead dominates.

## foculus π computation on GPU

the same GPU running proofs also computes foculus π iteration:

```
SpMV (sparse matrix-vector multiply):
  A100: ~50M edges at 40 Hz = 2×10⁹ edge ops/s

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
- **Binius lens**: binary operations are 128× more data-parallel on GPU (128 F₂ elements per word). binary proving on GPU is extremely efficient — the packing advantage multiplies the GPU parallelism advantage

## open questions

1. **Fiat-Shamir sequentiality**: hemera sponge is sequential (each squeeze depends on previous absorb). transcript processing cannot be parallelized. for short transcripts (~100 absorptions) this is negligible. for long interactive proofs, it may bottleneck
2. **VRAM capacity**: 2³⁰ trace = 16 GB fills consumer GPU. tensor trace compression (Horizon 5) reduces memory to O(√N), enabling large traces on consumer hardware
3. **kernel launch overhead**: WGSL compute dispatches have ~5-10 μs overhead. minimize dispatch count by fusing pipeline stages into larger kernels
4. **mixed precision**: GPU hardware has fast f16/f32 paths. Goldilocks is u64. no hardware acceleration for 64-bit field arithmetic on current GPUs. future GPU architectures (or GFP custom silicon) would change this

see [[zheng-2]] for unified architecture, [[proof-horizons]] for composition strategy, [[binius-pcs]] for binary GPU proving