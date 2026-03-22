---
tags: cyber, cip
crystal-type: process
crystal-domain: cyber
status: draft
diffusion: 0.00010722364868599256
springs: 0.00007019991600688145
heat: 0.00003419142694206788
focus: 0.00008151008453347325
gravity: 0
density: 0
---
# universal accumulator — one proof for everything

fold all proof obligations — signal validity, state integrity, cross-index consistency, content availability, physical time — into a single HyperNova accumulator. one constant-size object that proves everything about the chain from genesis to now.

## current proof obligations

each block produces multiple independent proofs:

```
per signal:    zheng proof (cyberlink validity + impulse)
per block:     LogUp proof (cross-index consistency across 9 NMTs)
per index:     NMT completeness proofs (state integrity)
per sync:      DAS proofs (content availability)
per signal:    VDF proof (physical time)

checkpoint:    BBG_root + folding_acc + block_height (~500 bytes)
```

these proofs are verified independently. a light client joining the network must understand multiple proof types and verify each.

## the target

```
universal_acc = fold(
  signal_proofs,          all cyberlink validity from genesis
  state_proofs,           all NMT state transitions
  cross_index_proofs,     all LogUp consistency checks
  availability_proofs,    all DAS sampling results
  time_proofs             all VDF verifications
)

checkpoint:    universal_acc (~200 bytes)
verification:  one decider proof, 10-50 μs
guarantee:     ALL history valid, ALL state correct,
               ALL cross-indexes consistent, ALL content available
```

## how HyperNova enables this

HyperNova folds CCS instances. CCS is general enough to encode any constraint system — R1CS, Plonkish, AIR, custom gates. different proof types have different constraint structures, but all are CCS instances.

the universal accumulator folds heterogeneous CCS instances:

```
fold(acc, signal_ccs_instance)       → acc'     (cyberlink proof)
fold(acc', logup_ccs_instance)       → acc''    (cross-index proof)
fold(acc'', nmt_ccs_instance)        → acc'''   (state proof)
fold(acc''', das_ccs_instance)       → acc''''  (availability proof)
fold(acc'''', vdf_ccs_instance)      → acc''''' (time proof)

each fold: ~30 field ops + 1 hemera hash
total per block: ~150 field ops + 5 hemera hashes
= ~4,500 F_p constraints per block for ALL proof composition
```

compare to independent verification: hundreds of thousands of constraints per block.

## light client experience

### current (multiple proof types)

```
light client joins:
  1. download checkpoint (BBG_root + folding_acc)
  2. verify folding_acc (one zheng decider, ~50 μs)
  3. sync namespace proofs (NMT, per-index)
  4. verify DAS samples (per-content)
  5. check VDF continuity (per-signal chain)

  total: multiple verification rounds, type-specific logic
```

### universal (one proof)

```
light client joins:
  1. download checkpoint (universal_acc, ~200 bytes)
  2. verify ONE decider proof (~10-50 μs)
  3. done — full confidence in entire chain history

  sync: request specific namespaces, verify against committed state
  all completeness and availability already proven in the accumulator
```

## cross-algebra support

the universal accumulator folds F_p and F₂ proofs into one object:

```
fold(acc, goldilocks_signal_proof)   → acc'     (F_p CCS)
fold(acc', binary_inference_proof)   → acc''    (F₂ CCS via universal selector)
fold(acc'', goldilocks_state_proof)  → acc'''   (F_p CCS)

universal CCS selectors:
  sel_Fp:  1 for Goldilocks instances
  sel_F2:  1 for binary instances
  sel_any: structural constraints (shared)
```

one accumulator, both algebras. the decider runs in F_p (hemera-native).

## epoch folding

within a block: fold individual signal proofs.
across blocks: fold block accumulators.
across epochs: fold epoch accumulators.

```
signal₁ ... signal_n → block_acc
block₁ ... block_m   → epoch_acc
epoch₁ ... epoch_k   → genesis_to_now_acc

each level: ~30 field ops per fold
total from genesis to block 10⁹: ~30 × 10⁹ field ops accumulated
but the accumulator is CONSTANT SIZE regardless
```

a node that was offline for a year downloads one accumulator and one decider proof. verified in 10-50 μs. equivalent to replaying every block since genesis — without actually replaying anything.

## relation to existing proposals

extends [[proof-horizons]] Horizon 2 (folding-first composition):
- Horizon 2 folds zheng proofs (signal validity) into block accumulators
- this proposal folds ALL proof types (state, availability, time) into one universal accumulator
- the composition mechanism is the same (HyperNova over CCS)
- the scope is broader — not just signal proofs but the entire verification stack

## open questions

1. **heterogeneous CCS efficiency**: folding instances with very different constraint counts (signal: ~13K, LogUp: ~5M, DAS: ~1K) may require padding or multi-sized accumulator slots. CycleFold addresses this but adds complexity
2. **availability proof freshness**: DAS proofs are probabilistic (O(√n) samples). folding a probabilistic proof into a deterministic accumulator requires care — the accumulator proves "sampling was performed correctly" not "data is available forever"
3. **VDF chain verification**: VDF proofs are sequential by nature. folding them doesn't remove the sequentiality — it just proves the chain was verified. a reconnecting node still needs to trust the VDF chain or re-verify critical segments
4. **accumulator size vs verification time trade-off**: a smaller accumulator (~200 bytes) may require a slightly more expensive decider. the optimal balance depends on light client profile (mobile vs desktop)

see [[proof-horizons]] for folding-first composition, [[zheng-2]] for architecture, [[binius-pcs]] for cross-algebra folding