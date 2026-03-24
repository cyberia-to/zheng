---
tags: cyber, cip
crystal-type: process
crystal-domain: cyber
status: accepted
date: 2026-03-17
origin: proof-horizons.md horizon 4
diffusion: 0.00010722364868599256
springs: 0.00007019991600688145
heat: 0.00003419142694206788
focus: 0.00008151008453347325
gravity: 0
density: 0
---
# gravity commitment — mass-weighted polynomial encoding

verification cost proportional to query importance, not data size. high-π particles verify faster. the proof system reflects the topology of attention.

## the observation

in the cybergraph, access follows a power law. π_i (cyberank) measures the probability of visiting particle i. a small fraction of particles accounts for most queries. standard polynomial commitments treat all positions equally — opening position 0 costs the same as opening position 2²⁰.

## the construction

encode the trace as a weighted polynomial where priority rows get lower-degree representation:

```
standard encoding:
  f(x₁, ..., xₙ) = Σ T[b] × eq(x, b)
  every term has equal weight
  opening at any point: same cost

gravity encoding:
  sort rows by priority (π rank)
  encode top-k rows in first k coefficients of lower-degree polynomial
  remaining rows in higher-degree extension
  opening lower-degree part: fewer WHIR/Brakedown rounds
```

### layered commitment

```
layer 0 (hot):    top 2⁸ rows   → degree 2⁸ polynomial  → 8 folding rounds
layer 1 (warm):   next 2¹² rows → degree 2¹² polynomial → 12 folding rounds
layer 2 (cold):   remaining     → degree 2²⁰ polynomial → 20 folding rounds

hot opening:    ~1 KiB proof, ~10 μs verify
warm opening:   ~3 KiB proof, ~50 μs verify
cold opening:   ~8 KiB proof, ~200 μs verify
```

## application to bbg

```
top-1000 neuron balance:     ~1 KiB proof, ~10 μs
obscure particle edge set:   ~8 KiB proof, ~200 μs
average (power-law queries): ~3 KiB, ~30 μs
```

the proof system adapts to the information structure of the data. important facts are cheaper to verify.

## weight function

the weight function maps positions to priority layers. natural choices:

- **π (cyberank)**: direct attention measure. highest-π particles in hot layer
- **access frequency**: empirical query rate. cached in CozoDB
- **stake-weighted**: neuron stake determines layer. higher-stake neurons verify faster

the weight function is committed alongside the polynomial. weight changes (π updates) require re-layering — but the polynomial VALUES don't change, only their layer assignment.

## open questions

1. **weight stability**: if π changes significantly between epochs, the layered structure must be re-committed. cost: one full re-encoding per epoch. acceptable if epochs are long (hours/days)
2. **soundness per layer**: each layer has different degree bounds. Schwartz-Zippel analysis must account for the weakest layer (highest degree). 2²⁰ degree over |F| ≈ 2⁶⁴ gives 2⁴⁴ bits of security per round — sufficient
3. **cross-layer queries**: querying a position that moved between layers requires opening the new layer. the verifier must know which layer contains the position — committed in the weight map

see [[zheng-2]] for integrated architecture, [[algebraic-extraction]] for batch opening