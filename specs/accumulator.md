---
tags: cyber, computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: universal accumulator, universal proof accumulator
---
# accumulator

the universal accumulator folds ALL proof obligations — signal validity, state integrity, cross-index consistency, content availability, physical time — into a single HyperNova accumulator. one constant-size object (~200 bytes) that proves everything about the chain from genesis to now. verification: one decider proof, 10-50 μs.

## proof obligations

each block produces multiple independent proofs:

```
per signal:    zheng proof (cyberlink validity + impulse)
per block:     LogUp proof (cross-index consistency across 9 NMTs)
per index:     NMT completeness proofs (state integrity)
per sync:      DAS proofs (content availability)
per signal:    VDF proof (physical time)
```

the universal accumulator folds all of these into one object.

## the accumulator

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

## HyperNova folding of heterogeneous CCS

HyperNova folds CCS instances. CCS is general enough to encode any constraint system — R1CS, Plonkish, AIR, custom gates. different proof types have different constraint structures, but all are CCS instances.

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

## five-layer folding

the accumulator folds all five structural sync layers into one object:

```
layer 1 (validity):      zheng proof per signal → folded into accumulator
layer 2 (ordering):      hash chain + VDF verification → folded
layer 3 (completeness):  NMT/polynomial update proof → folded
layer 4 (availability):  DAS commitment proof → folded
layer 5 (merge):         CRDT/foculus state transition → folded

result: one ~200 byte accumulator proves ALL five properties for ALL history
```

the accumulator proves "the entire sync protocol was executed correctly at every step since genesis."

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

## light client verification

```
light client joins:
  1. download checkpoint (universal_acc, ~200 bytes)
  2. verify ONE decider proof (~10-50 μs)
  3. done — full confidence in entire chain history

  sync: request specific namespaces, verify against committed state
  all completeness and availability already proven in the accumulator
```

## cross-algebra support

the accumulator folds F_p and F₂ proofs into one object:

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

## open questions

1. **heterogeneous CCS efficiency**: folding instances with very different constraint counts (signal: ~13K, LogUp: ~5M, DAS: ~1K) may require padding or multi-sized accumulator slots. CycleFold addresses this but adds complexity
2. **availability proof freshness**: DAS proofs are probabilistic (O(√n) samples). folding a probabilistic proof into a deterministic accumulator requires care — the accumulator proves "sampling was performed correctly" not "data is available forever"
3. **VDF chain verification**: VDF proofs are sequential by nature. folding them doesn't remove the sequentiality — it just proves the chain was verified. a reconnecting node still needs to trust the VDF chain or re-verify critical segments
4. **accumulator size vs verification time trade-off**: a smaller accumulator (~200 bytes) may require a slightly more expensive decider. the optimal balance depends on light client profile (mobile vs desktop)

see [[recursion]] for HyperNova folding protocol, [[binius]] for cross-algebra folding, [[lens]] for polynomial commitment
