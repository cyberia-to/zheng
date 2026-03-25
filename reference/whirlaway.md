---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: zheng architecture, zheng-2, multilinear stark architecture, Whirlaway
diffusion: 0.00042890433139523105
springs: 0.0002783187123873627
heat: 0.00033591611256587824
focus: 0.0003651310019269953
gravity: 12
density: 0.96
---
# zheng

the proof architecture for [[cyber]]. [[SuperSpartan]] IOP + [[Brakedown]] PCS (Goldilocks) + [[Binius]] PCS (F₂) + [[HyperNova]] folding. two PCS backends over one field-generic IOP. [[hemera]] is the only hash. 14 [[nox]] languages map to 2 provers. cross-algebra composition via universal CCS folding.

zheng-1 ("Whirlaway") used SuperSpartan + WHIR. zheng-2 replaces WHIR with Brakedown as the primary PCS and adds HyperNova folding for composition.

## architecture

```
zheng-2
├── IOP layer (field-generic, shared)
│   ├── SuperSpartan          CCS constraint system
│   ├── sumcheck              exponential sum reduction
│   └── HyperNova             folding + composition
│
├── PCS layer (field-specific, two backends)
│   ├── Brakedown (Goldilocks) expander-graph codes, Merkle-free (primary)
│   ├── Binius (F₂ tower)     binary Reed-Solomon with packing
│   └── WHIR (Goldilocks)     Reed-Solomon + Merkle (legacy, bootstrap)
│
├── hash layer
│   └── hemera                one hash, universal
│                             Fiat-Shamir for all PCS backends
│                             Merkle only for Binius/WHIR (not Brakedown)
│
└── composition
    └── HyperNova folding     ~30 field ops + 1 hemera hash per fold
        └── decider           one SuperSpartan + sumcheck + Brakedown proof
```

## composition

```
zheng = SuperSpartan (IOP for CCS)
      + Brakedown (multilinear PCS, primary)
      + HyperNova (folding composition)

prover:
  1. execute program → trace matrix (2ⁿ × 2ᵐ)
  2. commit trace as multilinear polynomial via Brakedown_commit
  3. run sumcheck with verifier (constraint verification via SuperSpartan)
  4. open Brakedown commitment at sumcheck output point

verifier:
  1. check sumcheck transcript (field arithmetic only)
  2. check Brakedown opening (matrix-vector consistency check)
  3. all constraints verified
```

## protocol specification

```
SETUP: none (transparent)

PROVER(trace T, constraints C):
  1. pad T to 2^n rows
  2. f ← multilinear_extension(T)        // f: F^{n+m} → F
  3. C_f ← Brakedown_commit(f)           // expander-graph encoding, O(N) field ops
  4. transcript.absorb(hemera(C_f))       // one binding hash
  5. for round i = 1..n+m:               // SuperSpartan sumcheck
       g_i ← sum_{remaining vars} constraint_poly(f, ...)
       transcript.absorb(g_i)
       r_i ← transcript.squeeze()
  6. v ← f(r_1, ..., r_{n+m})
  7. π ← Brakedown_open(f, (r_1,...,r_{n+m}))   // O(√N) field elements
  8. return (C_f, sumcheck_transcript, v, π)

VERIFIER(statement S, proof):
  1. transcript.absorb(S, hemera(proof.commitment))
  2. for round i = 1..n+m:
       check g_i(0) + g_i(1) = claim_{i-1}
       r_i ← transcript.squeeze()
       claim_i ← g_i(r_i)
  3. check claim_{n+m} = constraint_eval(proof.v, r, S)
  4. check Brakedown_verify(proof.commitment, r, proof.v, proof.π)
```

## multilinear extension

the trace matrix T (2^n rows × 2^m columns, m=4) is encoded as a single multilinear polynomial f over F^{n+m}. this is the unique polynomial of degree ≤ 1 in each variable that agrees with the trace on all binary inputs.

### definition

```
for any binary vector (b₁,...,b_n, c₁,...,c_m) ∈ {0,1}^{n+m}:
  f(b₁,...,b_n, c₁,...,c_m) = T[row(b₁...b_n), col(c₁...c_m)]

where row(b₁...b_n) = Σ bᵢ × 2^{n-i}  (binary → integer)
      col(c₁...c_m) = Σ cⱼ × 2^{m-j}
```

### evaluation at arbitrary point

to evaluate f at an arbitrary field point r = (r₁,...,r_{n+m}):

```
f(r₁,...,r_{n+m}) = Σ_{b ∈ {0,1}^{n+m}} T[b] × eq(r, b)

where eq(r, b) = ∏ᵢ (rᵢ × bᵢ + (1 - rᵢ) × (1 - bᵢ))
```

eq(r, b) is the multilinear Lagrange basis polynomial: it equals 1 when r = b (on binary inputs) and interpolates smoothly elsewhere. the sum runs over all 2^{n+m} trace entries.

### streaming evaluation algorithm

```
EVAL_MLE(trace T, point r = (r₁,...,r_k)):   // k = n + m
  table ← flatten(T)                          // 2^k entries
  for i in 1..k:
    half ← len(table) / 2
    for j in 0..half:
      table[j] ← table[2j] × (1 - rᵢ) + table[2j+1] × rᵢ
    table ← table[0..half]
  return table[0]

cost: 2^k + 2^{k-1} + ... + 1 = 2^{k+1} - 1 ≈ 2N field operations
memory: in-place, modifies table of shrinking size
```

this is the same algorithm the sumcheck prover uses internally: each round fixes one variable, halving the table. after k rounds, one value remains.

## two PCS backends

### Goldilocks path (primary)

12 of 14 nox languages encode as F_p constraints and use Brakedown:

| language | algebra | constraint type |
|---|---|---|
| Tri | F_{p^n} field tower | native field arithmetic |
| Tok | UTXO conservation | field arithmetic + hemera membership |
| Arc | category theory | tree traversal + hemera hashing |
| Seq | partial order | structural comparisons |
| Inf | Horn clauses | unification + resolution |
| Bel | g on Delta^n | fixed-point Bayes |
| Ren | G(p,q,r) shapes | fixed-point geometry |
| Dif | (M, g) manifolds | discretized derivatives |
| Sym | (M, omega) dynamics | Hamiltonian integration |
| Wav | R_q convolution | NTT multiply (ring-aware jets) |
| Ten | contraction (full-precision) | matrix multiply |
| Rs | Z/2^n words (arithmetic-heavy) | word arithmetic + range checks |

### binary path

2 of 14 languages encode as F₂ constraints and use Binius:

| language | algebra | constraint type |
|---|---|---|
| Bt | F₂ tower | native binary (XOR=add, AND=mul) |
| Ten | contraction (quantized) | 1-4 bit matrix multiply |

## instantiation in cyber

| parameter | value |
|---|---|
| field | [[Goldilocks field]] (p = 2^64 − 2^32 + 1) |
| hash | [[hemera]] (Poseidon2, 512-bit state, 256-bit capacity) |
| VM | [[nox]] (16 patterns + hint + 5 jets) |
| IOP | [[SuperSpartan]] over [[CCS]] |
| PCS (primary) | [[Brakedown]] (multilinear, Merkle-free) |
| PCS (binary) | [[Binius]] (F₂ tower) |
| PCS (legacy) | [[WHIR]] (multilinear, Merkle-based) |
| composition | [[HyperNova]] folding over CCS |
| trace width | 16 registers (2^4 columns) |
| trace depth | up to 2^32 rows |
| constraint system | CCS encoding of AIR (see [[constraints]]) |
| Fiat-Shamir | [[hemera]] sponge (see [[transcript]]) |

## cost model

### prover

| phase | cost | dominant operation |
|---|---|---|
| execute | O(N) nox steps | VM reduction |
| encode | O(N) | multilinear extension (field ops) |
| commit | O(N) | Brakedown expander-graph encoding (field ops) |
| sumcheck (SuperSpartan) | O(N) | field multiplications |
| Brakedown open | O(N) | linear combination of encoded rows |
| total | O(N) | field-op dominated (nebu) |

with WHIR (legacy): commit O(N log N), open O(N log N), total O(N log N), hash-dominated (hemera).

### verifier

| phase | cost | operations |
|---|---|---|
| sumcheck check | O(log N) | field arithmetic only |
| Brakedown verify | O(λ log log N) | field arithmetic (recursive tensor check) |
| total | O(λ log log N) | field-dominated |
| wall clock (128-bit) | ~5 μs | field ops only |

with WHIR (legacy): verify O(log² N), ~1.0 ms at 128-bit, hash-dominated (~2,700 hemera calls).

### proof size

| PCS | size (128-bit) | breakdown |
|---|---|---|
| Brakedown | ~2 KiB | sumcheck (~0.5 KiB) + evaluation (~0.3 KiB) + Brakedown opening (~1.3 KiB) |
| WHIR (legacy) | ~157 KiB | sumcheck (~3 KiB) + WHIR opening (~154 KiB) |

proof size is constant regardless of original computation size.

## why this composition

[[SuperSpartan]] is PCS-agnostic — it works with any polynomial commitment scheme. choosing [[Brakedown]] as the primary PCS gives:

| property | source |
|---|---|
| transparent setup | Brakedown (no ceremony, no trusted setup) |
| post-quantum security | Brakedown (no discrete log, no pairings) |
| O(N) commitment | Brakedown (expander-graph encoding, no FFT) |
| O(λ log log N) verification | Brakedown (recursive tensor check, no Merkle) |
| linear-time constraint proving | SuperSpartan (sumcheck, no FFT) |
| any-degree AIR constraints | SuperSpartan ([[CCS]] generality) |
| one commitment, one opening | multilinear encoding + sumcheck reduction |
| HyperNova folding | ~30 field ops per recursive step |

| PCS | setup | post-quantum | verification | verifier constraints |
|---|---|---|---|---|
| **Brakedown** | none | yes | ~5 μs | ~8K |
| WHIR | none | yes | ~1.0 ms | ~70K |
| KZG | trusted ceremony | no | ~2.4 ms | — |
| FRI | none | yes | ~3.9 ms | — |
| STIR | none | yes | ~3.8 ms | — |

Brakedown eliminates Merkle trees from the PCS. the 83% of WHIR's verifier constraints that were Merkle verification disappear entirely.

## recursive closure

the zheng verifier uses only:
- [[Goldilocks field]] arithmetic (nox patterns 5-8)
- [[hemera]] hashing (nox pattern 15 / hash jet) — Fiat-Shamir only
- conditional branching (nox pattern 4)

these are all [[nox]]-native operations. the verifier is a nox program. zheng can prove its own verification. with recursive Brakedown, the recursive verifier drops to ~8,000 constraints (from ~70,000 with WHIR) because Merkle path verification is eliminated and the opening check compresses to O(λ log log N) field ops.

HyperNova folding further reduces recursive composition: ~30 field ops + 1 hemera hash per fold step, with one decider proof at the end.

see [[verifier]] for the verification algorithm, [[api]] for the prover/verifier interface, [[recursion]] for recursive composition, [[constraints]] for the AIR format, [[transcript]] for Fiat-Shamir construction