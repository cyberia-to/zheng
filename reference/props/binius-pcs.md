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
# binius PCS — binary-native polynomial commitment

a second PCS backend for zheng operating over F₂ tower fields. the IOP layer (SuperSpartan + sumcheck + HyperNova) stays field-generic. only the polynomial commitment scheme changes. hemera remains the only hash — used externally for Merkle commitment and Fiat-Shamir, never proved inside binary circuits.

## motivation

nox bitwise patterns (xor, and, not, shl, lt) cost 32-64 STARK constraints each in F_p because bit decomposition is expensive in a prime field. in F₂, they cost 1 constraint each. the 32× gap is not a design flaw — it is the honest algebraic distance between F_p and F₂.

two workloads dominate the binary regime:
- **quantized AI inference**: BitNet-style 1-bit models. matrix-vector multiply = XOR + popcount. a 4096×4096 layer = ~16M binary constraints (vs ~512M F_p constraints)
- **tri-kernel SpMV**: quantized axon weights for π iteration over the cybergraph. each of 5-8 iterations is a massive binary workload

## architecture

```
zheng
├── IOP:          SuperSpartan + sumcheck     (field-generic, shared)
├── Composition:  HyperNova folding           (field-generic, shared)
├── Hash:         hemera                      (one hash, universal)
├── PCS₁:         WHIR (Goldilocks)           (existing)
└── PCS₂:         Binius (F₂ tower)           (this proposal)
```

zheng exposes a PCS trait. WHIR and Binius both implement it:

```
trait PCS<F: Field> {
    fn commit(poly: &MultilinearPoly<F>) -> Commitment;
    fn open(poly: &MultilinearPoly<F>, point: &[F]) -> Opening;
    fn verify(commitment: &Commitment, point: &[F], value: F, proof: &Opening) -> bool;
}
```

## Binius PCS specifics

### binary tower fields

F₂ → F₂² → F₂⁴ → F₂⁸ → F₂¹⁶ → F₂³² → F₂⁶⁴ → F₂¹²⁸

each extension defined by irreducible polynomial over the previous level. tower structure enables:
- 128 F₂ elements packed in one u128 machine word
- SIMD-native operations (64× data parallelism vs Goldilocks)
- Karatsuba multiplication over tower levels

### commitment

polynomial evaluations arranged in a matrix. rows packed into machine words. hemera Merkle tree over packed rows.

```
commit(poly over F₂):
  1. arrange evaluations in √n × √n matrix
  2. pack each row into machine words (128 F₂ elements per u128)
  3. Reed-Solomon extend rows over F₂¹²⁸
  4. build hemera Merkle tree over extended rows
  5. root = hemera hash (same as WHIR commitment)
```

hemera operates on bytes — it doesn't care that the bytes represent binary field elements. same hemera::hash_node, same tree primitives, same 32-byte root.

### opening

Binius folding: each round halves the polynomial by combining rows using a random F₂¹²⁸ challenge.

```
open(poly, point):
  for each folding round:
    squeeze challenge from hemera Fiat-Shamir transcript
    fold polynomial (halve rows)
    commit folded polynomial (hemera Merkle)
  return final value + all round commitments + Merkle auth paths
```

### verification

```
verify(commitment, point, value, proof):
  replay Fiat-Shamir (hemera sponge)
  check folding consistency (F₂ field arithmetic)
  check Merkle auth paths (hemera)
  check final evaluation
```

the verifier uses hemera for hashing and F₂ for field ops. no binary-native hash needed.

## cross-algebra composition

a mixed nox program (field + bitwise) partitions into sub-traces:

```
nox<F_p> sub-trace → zheng<WHIR> proof
nox<F₂>  sub-trace → zheng<Binius> proof
                           ↓
            HyperNova fold into shared F_p accumulator
            cost: ~30 F_p field ops + 1 hemera hash per fold
```

universal CCS with selectors enables heterogeneous folding:

```
universal_ccs = {
  sel_Fp:  1 for Goldilocks rows, 0 otherwise
  sel_F2:  1 for binary rows, 0 otherwise
}
```

one accumulator covers both algebras. the decider runs once in F_p (hemera-native).

## recursion boundary

binary proofs are NOT verified inside binary circuits. verification crosses to Goldilocks:

```
binary execution → binary proof (hemera Merkle + FS externally)
                        ↓
    verify in F_p circuit (hemera native, ~70K constraints with jets)
                        ↓
    fold into F_p accumulator
```

hemera inside F₂ circuit: ~142K binary constraints per hash (simulating Goldilocks mul in bits). unacceptable for recursion. hemera inside F_p circuit: ~736 constraints (hemera-2). the recursion boundary is Goldilocks.

## kuro dependency

a new repo **kuro** (黒) provides F₂ tower arithmetic:
- F₂ base field operations (XOR = add, AND = mul)
- tower extension arithmetic (F₂² through F₂¹²⁸)
- packed SIMD operations (128 elements per u128)
- no hemera dependency, no nebu dependency
- pure binary algebra

zheng depends on kuro for the Binius PCS backend. hemera remains the only hash throughout.

## cost comparison

| operation | F_p (WHIR) | F₂ (Binius) | ratio |
|---|---|---|---|
| AND | ~32 constraints | 1 constraint | 32× |
| XOR | ~32 constraints | 1 constraint | 32× |
| lt (comparison) | ~64 constraints | ~1 constraint | 64× |
| field multiply | 1 constraint | ~64 constraints | 0.016× |
| hemera hash | ~736 constraints | N/A (external) | — |

binary wins for bitwise. Goldilocks wins for arithmetic. the prover chooses based on workload.

## open questions

1. **packed trace layout**: nox trace spec (16 registers × 2ⁿ rows) needs binary variant with 128-bit packing
2. **cross-algebra value transfer**: quantize/dequantize at F_p ↔ F₂ boundary — concrete constraint cost
3. **optimal partition granularity**: how large should binary sub-traces be before boundary overhead dominates
4. **kuro SIMD strategy**: AVX-512 (512 elements), AVX2 (256 elements), or portable u128

see [[algebra-polymorphism]] for nox instantiation model, [[zheng-2]] for unified architecture, [[proof-horizons]] for composition strategy