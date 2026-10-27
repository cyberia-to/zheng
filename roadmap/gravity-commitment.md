---
tags: cyber, cip
crystal-type: process
crystal-domain: cyber
status: accepted
date: 2026-03-17
origin: proof-horizons.md horizon 4
---
# gravity commitment — mass-weighted polynomial encoding

> superseded: written for the retired expander-code ("recursive Brakedown") lens; its figures were never measured and are removed. the idea is restated below for the shipped Reed–Solomon/WHIR commitment ([[soft3/proposals/proof-system-repair|proof-system repair]]).

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
  opening lower-degree part: fewer WHIR folding rounds, shorter Merkle paths
```

### layered commitment

```
layer 0 (hot):    top 2⁸ rows   → 8-variable multilinear polynomial
layer 1 (warm):   next 2¹² rows → 12-variable multilinear polynomial
layer 2 (cold):   remaining     → 20-variable multilinear polynomial

each layer is its own Reed–Solomon commitment under its own hemera root.
an opening's size and verify time grow with the layer's variable count
(WHIR rounds, Merkle path depth), so hot openings are the cheapest.
no figure is claimed until measured on the shipped parameters.
```

for scale, the one measured WHIR opening at this time: a 2^10-slot witness opens inside a 15,921 B succinct proof verified in 7.96 ms, and a 2^20 relation in 71,081 B and 270 ms (`audit/succinct-profile-2026-10.md`). a hash-only opening carries Merkle paths, so a hot layer is cheaper than a cold one by a constant factor, not by orders of magnitude.

## application to bbg

top-1000 neuron balances would sit in the hot layer and open cheapest;
an obscure particle's edge set in the cold layer. the average cost under
power-law queries is to be measured once the BBG `QueryProof` rides
the shipped commitment.

the proof system adapts to the information structure of the data. important facts are cheaper to verify.

## weight function

the weight function maps positions to priority layers. natural choices:

- **π (cyberank)**: direct attention measure. highest-π particles in hot layer
- **access frequency**: empirical query rate. cached in CozoDB
- **stake-weighted**: neuron stake determines layer. higher-stake neurons verify faster

the weight function is committed alongside the polynomial. weight changes (π updates) require re-layering — but the polynomial VALUES don't change, only their layer assignment.

## open questions

1. **weight stability**: if π changes significantly between epochs, the layered structure must be re-committed. cost: one full re-encoding per epoch. acceptable if epochs are long (hours/days)
2. **soundness per layer**: each layer has different degree bounds. Schwartz-Zippel analysis must account for the weakest layer (highest degree). 2²⁰ degree over |F| ≈ 2⁶⁴ would leave only about 44 bits per round, so challenges must come from Fp3 (|F| ≈ 2^192), as in every zheng profile
3. **cross-layer queries**: querying a position that moved between layers requires opening the new layer. the verifier must know which layer contains the position — committed in the weight map

see [[zheng-2]] for integrated architecture, [[algebraic-extraction]] for batch opening