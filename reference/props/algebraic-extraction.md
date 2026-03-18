---
tags: cyber, cip
crystal-type: process
crystal-domain: cyber
status: accepted
date: 2026-03-17
origin: proof-horizons.md horizon 1
---
# algebraic Merkle extraction

replace individual Merkle path openings in WHIR with a single batch algebraic opening. proof size: 60-157 KiB → 5-12 KiB. recursive verifier: ~50K constraints → ~5K constraints.

## the bottleneck

77% of zheng-1 proof size is Merkle authentication paths. 71% of recursive verifier cost is Merkle path checking:

```
proof composition (128-bit security):
  total proof:           157 KiB
    Merkle auth paths:   121 KiB  (77%)
    leaf values:          22 KiB  (14%)
    round commitments:    14 KiB  (9%)

recursive verifier (70K constraints with jets):
    Merkle verification:  50K  (71%)
    everything else:      20K  (29%)
```

## the construction

given k query positions (x₁, ..., xₖ) and claimed values (v₁, ..., vₖ):

```
prover:
  1. construct vanishing polynomial Z(x) = ∏(x - xᵢ)    [degree k]
  2. construct quotient Q(x) = (f(x) - I(x)) / Z(x)     [degree N-k]
     where I(x) interpolates the claimed values at query points
  3. commit to Q via a single hemera hash chain (not a tree)
  4. run sumcheck to verify: f(r) - I(r) = Q(r) · Z(r)   [one field equation]

verifier:
  1. compute Z(r) from known query positions              [k muls]
  2. compute I(r) from known values + positions            [k muls]
  3. check sumcheck transcript                             [log N rounds]
  4. check Q(r) via one WHIR evaluation                   [one opening]
  5. verify: f(r) - I(r) = Q(r) · Z(r)                   [1 field equation]
```

## why this works

the Merkle tree in WHIR serves two purposes: binding (commitment) and evaluation proof (opening). the Merkle root stays for binding. for opening, k separate tree walks are replaced by one algebraic batch argument.

the key: verifying "f equals these k values at these k positions" is the same as verifying "Z divides f - I" which requires only one evaluation of the quotient Q.

security: if the prover cheats on any evaluation point, f - I does NOT vanish at that point, Q has a pole, Q is not low-degree, WHIR rejects Q's commitment.

## cost comparison

```
                      current (WHIR)           algebraic extraction
proof size (128-bit): ~157 KiB                  ~12 KiB
proof size (100-bit): ~60 KiB                   ~5 KiB
verifier hashes:      ~2,700                    ~400
verify time:          ~1.0 ms                   ~150 μs
recursive constraints: ~50K (Merkle)            ~5K (sumcheck + 1 opening)
```

## relation to brakedown

algebraic extraction optimizes WHIR by replacing the opening mechanism. Brakedown ([[brakedown-pcs]]) goes further — eliminates the Merkle tree from commitment entirely.

- **near-term**: algebraic extraction on WHIR (keeps existing infrastructure, 20× improvement)
- **long-term**: Brakedown replaces WHIR (eliminates hashing from proofs, 30-150× improvement)

both compose with folding-first, proof-carrying, gravity, and tensor compression.

## open questions

1. **soundness over Goldilocks**: does the Schwartz-Zippel bound over |F| ≈ 2⁶⁴ give sufficient security margin accumulated over multiple sumcheck rounds?
2. **Q commitment size**: Q has degree N-k. can the commitment use a shorter chain structure since the verifier only needs Q at one random point?

see [[zheng-2]] for integrated architecture, [[brakedown-pcs]] for Merkle-free approach
