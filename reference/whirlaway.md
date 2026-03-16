---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: Whirlaway, Whirlaway architecture, multilinear stark architecture
---
# whirlaway

the concrete multilinear [[stark]] architecture: [[SuperSpartan]] IOP + [[WHIR]] PCS. Habock, Levit, Papini (LambdaClass, 2025). [[zheng]] is [[cyber]]'s implementation.

## composition

```
Whirlaway = SuperSpartan (IOP for CCS) + WHIR (multilinear PCS)

prover:
  1. execute program → trace matrix (2ⁿ × 2ᵐ)
  2. commit trace as multilinear polynomial via WHIR_commit
  3. run sumcheck with verifier (constraint verification via SuperSpartan)
  4. open WHIR commitment at sumcheck output point via WHIR_open

verifier:
  1. check sumcheck transcript (field arithmetic only)
  2. check WHIR opening (one evaluation proof: WHIR_verify)
  3. all constraints verified
```

## protocol specification

```
SETUP: none (transparent)

PROVER(trace T, constraints C):
  1. pad T to 2^n rows
  2. f ← multilinear_extension(T)        // f: F^{n+m} → F
  3. C_f ← WHIR_commit(f)                // hemera Merkle root
  4. transcript.absorb(C_f)
  5. for round i = 1..n+m:               // SuperSpartan sumcheck
       g_i ← sum_{remaining vars} constraint_poly(f, ...)
       transcript.absorb(g_i)
       r_i ← transcript.squeeze()
  6. v ← f(r_1, ..., r_{n+m})
  7. π ← WHIR_open(f, (r_1,...,r_{n+m}))
  8. return (C_f, sumcheck_transcript, v, π)

VERIFIER(statement S, proof):
  1. transcript.absorb(S, proof.commitment)
  2. for round i = 1..n+m:
       check g_i(0) + g_i(1) = claim_{i-1}
       r_i ← transcript.squeeze()
       claim_i ← g_i(r_i)
  3. check claim_{n+m} = constraint_eval(proof.v, r, S)
  4. check WHIR_verify(proof.commitment, r, proof.v, proof.π)
```

## instantiation in cyber

| parameter | value |
|---|---|
| field | [[Goldilocks field]] (p = 2^64 − 2^32 + 1) |
| hash | [[hemera]] (Poseidon2, 512-bit state, 256-bit capacity) |
| VM | [[nox]] (16 patterns + hint + 5 jets) |
| IOP | [[SuperSpartan]] over [[CCS]] |
| PCS | [[WHIR]] (multilinear mode) |
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
| commit | O(N log N) | hemera Merkle tree construction |
| sumcheck (SuperSpartan) | O(N) | field multiplications |
| WHIR open | O(N log N) | hemera hashes + folding |
| total | O(N log N) | WHIR commit/open dominates |

### verifier

| phase | cost | operations |
|---|---|---|
| sumcheck check | O(log N) | field arithmetic only |
| WHIR verify | O(log² N) | hemera hashes + field ops |
| total | O(log² N) | hash-dominated |
| wall clock (128-bit) | ~1.0 ms | ~2,700 hemera calls |
| wall clock (100-bit) | ~290 μs | ~1,800 hemera calls |

### proof size

| security | size | breakdown |
|---|---|---|
| 100-bit | ~60 KiB | sumcheck (~2 KiB) + WHIR opening (~58 KiB) |
| 128-bit | ~157 KiB | sumcheck (~3 KiB) + WHIR opening (~154 KiB) |

proof size is constant regardless of original computation size.

## why this composition

[[SuperSpartan]] is PCS-agnostic — it works with any polynomial commitment scheme. choosing [[WHIR]] as the PCS gives:

| property | source |
|---|---|
| transparent setup | WHIR (hash-only, no ceremony) |
| post-quantum security | WHIR (no discrete log) |
| sub-millisecond verification | WHIR (weighted queries, rate improvement) |
| linear-time constraint proving | SuperSpartan (sumcheck, no FFT) |
| any-degree AIR constraints | SuperSpartan ([[CCS]] generality) |
| one commitment, one opening | multilinear encoding + sumcheck reduction |

the alternative PCS choices and their tradeoffs:

| PCS | setup | post-quantum | verification |
|---|---|---|---|
| KZG | trusted ceremony | no | ~2.4 ms |
| IPA | none | no | ~10 ms |
| [[FRI]] | none | yes | ~3.9 ms |
| [[STIR]] | none | yes | ~3.8 ms |
| WHIR | none | yes | ~1.0 ms |

WHIR is the only PCS that combines transparent setup, post-quantum security, and sub-millisecond verification.

## recursive closure

the Whirlaway verifier uses only:
- [[Goldilocks field]] arithmetic (nox patterns 5-8)
- [[hemera]] hashing (nox pattern 15 / hash jet)
- conditional branching (nox pattern 4)

these are all [[nox]]-native operations. the verifier is a nox program. zheng can prove its own verification — enabling recursive proof composition at ~70,000 constraints per level (with jets).

see [[verifier]] for the verification algorithm, [[api]] for the prover/verifier interface, [[recursion-spec]] for recursive composition, [[constraints]] for the AIR format, [[transcript]] for Fiat-Shamir construction
