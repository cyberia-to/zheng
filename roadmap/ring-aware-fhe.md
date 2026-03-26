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
# ring-aware FHE proving

specialized constraint encoding and jet library for proving FHE bootstrapping operations. not a third prover — the IOP (SuperSpartan + sumcheck) and composition (HyperNova) are unchanged. the ring structure of R_q is exploited at the constraint level through ring-structured CCS encodings and dedicated jets.

depends on [[goldilocks-fhe]]: mudra choosing q = Goldilocks prime makes all R_q operations native nebu NTT.

## FHE bootstrapping workload

TFHE bootstrapping refreshes ciphertext noise. four phases, each with a different algebraic character:

| phase | operation | algebra | language |
|---|---|---|---|
| gadget decomposition | bit-split coefficients | F₂ (binary) | Bt |
| blind rotation | n polynomial multiplies in R_q | F_p (NTT) | Wav |
| key switching | matrix × vector over F_p | F_p (matrix) | Ten |
| modulus switching | rescale coefficients | F_p (field) | Tri |

bootstrapping is a cross-language computation. each phase proves in its native algebra via the appropriate lens backend (WHIR or Binius). HyperNova folds across boundaries.

## where generic proving wastes work

a generic SuperSpartan prover treats each NTT multiply as independent degree-2 constraints. it doesn't see that blind rotation performs n structured polynomial multiplies over the same ring.

### NTT batching

blind rotation: n polynomial multiplies. each = NTT → pointwise → INTT.

```
generic:     n independent commitments
             n × O(N log N) hemera hashes for Merkle trees
             n × O(N) constraints for NTT correctness

ring-aware:  1 batch commitment to the entire rotation
             the NTT structure IS the evaluation domain
             commit once, prove n multiplies together

savings:     ~log(n) factor on commitment
             ~n factor on NTT correctness (proved once, not n times)
```

### automorphism exploitation

key switching uses Galois automorphisms of R_q: x → x^{5^k}. these permute NTT evaluation points.

```
generic:     each rotation = n F_p constraints
             (re-prove the permuted polynomial from scratch)

ring-aware:  each rotation = 1 permutation argument
             (prove the permutation, not the result)
             cost: O(log n) constraints via LogUp permutation check

savings:     ~n/log(n) per rotation
```

### noise budget tracking

FHE correctness requires noise below a threshold. generic provers check noise bounds per-operation (range checks on coefficients).

```
generic:     per-operation range check
             ~64 constraints per coefficient per operation
             n coefficients × m operations = 64nm constraints

ring-aware:  running noise accumulator
             fold noise bound through computation
             check once at end (decider)
             cost: ~30 field ops per fold step

savings:     ~64nm / (30m) = ~2n per operation
```

## jet library

recognized by formula hash, replace generic constraints with ring-structured ones:

```
fhe_bootstrap jets:
  ntt_batch(polys, n):
    recognize n polynomial multiplies sharing the same ring
    commit as single structured polynomial
    cost: O(n × N) instead of O(n × N log N)

  key_switch(ct, ks_key, k):
    recognize key switching matrix-vector multiply
    exploit automorphism structure as permutation argument
    cost: O(k × log N) instead of O(k × N)

  gadget_decomp(ct, base, levels):
    recognize binary decomposition of coefficients
    delegate to Binius lens for binary sub-trace
    cost: O(N × levels) binary constraints (1 each in F₂)

  noise_track(noise_bound, operation):
    fold noise bound into running accumulator
    check at bootstrapping boundary
    cost: ~30 field ops per fold
```

## cross-language bootstrapping flow

```
step 1: gadget_decomp(ct)          → Bt (F₂, Binius)
         fold into accumulator       ~766 F_p constraints

step 2: blind_rotation(decomposed)  → Wav (F_p, WHIR, ring-aware)
         ntt_batch jet               ~n × N constraints (batched)
         fold into accumulator       ~766 F_p constraints

step 3: key_switch(rotated, ks)     → Ten (F_p, WHIR)
         key_switch jet              ~k × log(N) constraints
         fold into accumulator       ~766 F_p constraints

step 4: mod_switch(switched)        → Tri (F_p, WHIR)
         ~N constraints              (coefficient rescaling)
         fold into accumulator       ~766 F_p constraints

total composition overhead: ~3,064 F_p constraints (4 boundary crossings)
total computation: dominated by step 2 (blind rotation)
```

## hemera under FHE

computing hemera homomorphically (FHE-friendly hashing) is a separate concern from proving FHE:

```
hemera multiplicative depth: 40 (x⁻¹ S-box, 16 partial rounds)
FHE noise growth:               5.4× less per hemera evaluation
bootstraps needed:              fewer → faster overall pipeline
```

the ring-aware jets prove that a hemera evaluation under FHE was computed correctly. hemera's reduced depth means the noise tracking accumulator triggers bootstrapping less often.

## open questions

1. **ring-structured CCS formalization**: encoding R_q operations as CCS matrices with ring structure. the "batched NTT" constraint needs a concrete CCS representation showing where the savings come from
2. **permutation argument for automorphisms**: LogUp permutation check in the key switching context. the permutation is algebraically structured (Galois group) — can this structure reduce the LogUp cost further?
3. **noise model precision**: the running noise accumulator tracks worst-case noise. if the actual noise is much lower (typical case), the accumulator over-provisions. adaptive noise tracking (tighten bounds when actual noise is measured) would improve throughput
4. **multi-key FHE**: bootstrapping with multiple keys (threshold FHE for multi-party computation). each key introduces a separate automorphism group. jet recognition across key boundaries

see [[goldilocks-fhe]] for parameter choice, [[binius-pcs]] for binary gadget decomposition, [[proof-horizons]] for composition strategy