---
tags: cyber, cip
crystal-type: process
crystal-domain: cyber
status: accepted
date: 2026-03-17
origin: proof-horizons.md horizon 2
diffusion: 0.00010722364868599256
springs: 0.00007019991600688145
heat: 0.00003419142694206788
focus: 0.00008151008453347325
gravity: 0
density: 0
---
# folding-first block composition

HyperNova folding as the primary composition mechanism at every level: transaction, block, epoch. recursive step: ~70K constraints → ~30 field operations. block proving: 1.4M → 70K constraints. epoch composition: 70M → 70K constraints.

## what changes

current block proving:

```
1000 transactions in a block:
  tree aggregation: 10 levels × 2 verifications × 70K constraints = 1.4M constraints
  total: ~1.4M constraints + N leaf proofs
```

folding-first:

```
1000 transactions in a block:
  fold: 1000 steps × ~30 field ops = 30K field operations (trivial)
  decider: 1 × 70K constraints
  total: ~70K constraints + 30K field ops

reduction: 20×
```

## epoch composition

```
current:
  block 1 → proof → verify-in-nox → proof → ...
  1000 blocks/epoch × 70K constraints/recursive verify = 70M constraints

folding-first:
  block 1 → fold → block 2 → fold → ... → block 1000 → fold → decider
  1000 folds × 30 field ops = 30K field ops
  1 decider = 70K constraints
  total: 70K constraints + negligible folding cost

reduction: 1000×
```

## cross-algebra folding

with algebra-polymorphic nox, different transactions may execute in different algebras (F_p, F₂, F_{p³}). universal CCS with selectors enables heterogeneous folding:

```
universal_ccs = {
  sel_Fp:  1 for Goldilocks rows, 0 otherwise
  sel_F2:  1 for binary rows, 0 otherwise
}
```

a nox<F_p> transaction activates sel_Fp rows. a nox<F₂> transaction activates sel_F2 rows. both fold into the same accumulator.

the decider proves the universal CCS instance. one proof regardless of how many algebras were involved.

boundary cost per cross-algebra fold: ~766 F_p constraints (30 field ops + 1 hemera-2 hash). negligible vs execution cost.

## extended by universal accumulator

folding-first composes signal validity proofs. [[universal-accumulator]] extends this to fold ALL proof types — signals, state integrity, cross-index consistency, DAS availability, VDF time — into one object.

## open questions

1. **universal CCS overhead**: padding smaller instances to match universal CCS dimensions wastes constraints. CycleFold addresses this but adds protocol complexity
2. **cross-algebra soundness**: does folding F_p and F₂ instances into the same accumulator preserve HyperNova security guarantees?

see [[zheng-2]] for integrated architecture, [[universal-accumulator]] for full-stack folding, [[binius-pcs]] for binary backend