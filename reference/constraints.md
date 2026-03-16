---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: AIR constraints, constraint encoding, zheng constraints
---
# constraints

the AIR constraint format and encoding rules for [[zheng]]. each [[nox]] reduction pattern maps to a polynomial transition constraint over the [[Goldilocks field]]. [[SuperSpartan]] verifies these constraints via [[CCS]] and the [[sumcheck]] protocol.

## constraint structure

a constraint is a polynomial equation C_p(t) that must equal zero at every trace row where pattern p fires:

```
C_p(t) = polynomial_expression(registers_at_row_t, registers_at_row_{t+1})
```

the combined constraint over all patterns:

```
C(t) = Σ_{p=0}^{16} selector_p(r0_t) × C_p(t)
```

where selector_p(r0_t) = 1 when r0_t = p, 0 otherwise. constructed via Lagrange interpolation over the 17 pattern values.

## pattern constraint table

| pattern | name | constraint | degree | count |
|---|---|---|---|---|
| 0 | axis | navigation through subject tree | 1 | ~depth |
| 1 | quote | r5_{t+1} = literal | 1 | 1 |
| 2 | compose | chain: eval x, eval y, eval result on x's output | 1 | 2 |
| 3 | cons | pair two sub-results | 1 | 2 |
| 4 | branch | selector × (next − yes) + (1 − sel) × (next − no) = 0 | 2 | 2 |
| 5 | add | r5_{t+1} = r3_t + r4_t | 1 | 1 |
| 6 | sub | r5_{t+1} = r3_t − r4_t | 1 | 1 |
| 7 | mul | r5_{t+1} = r3_t × r4_t | 2 | 1 |
| 8 | inv | r5_{t+1} × r3_t = 1 | 2 | 1 |
| 9 | eq | (r3_t − r4_t) × inv = flag, r5_{t+1} = 1 − flag | 2 | 1 |
| 10 | lt | range decomposition into 64 bits | 1 | ~64 |
| 11 | xor | bit decomposition + XOR per bit | 2 | ~64 |
| 12 | and | bit decomposition + AND per bit | 2 | ~64 |
| 13 | not | bitwise complement | 1 | ~64 |
| 14 | shl | shift via multiplication by 2^n | 2 | ~64 |
| 15 | hash | Poseidon2 round: state_{t+1} = MDS × (state_t)^7 | 7 | ~300 |
| 16 | hint | external constraint check (Layer 1 verification) | varies | varies |

## universal constraints

these hold at every row regardless of pattern:

### focus accounting

```
r7_t = r6_t - cost(r0_t)
```

focus_after = focus_before − pattern cost. cost is fixed per pattern.

### step index

```
r15_{t+1} = r15_t + 1
```

monotonically increasing step counter.

### halting

when r14_t transitions to halted, all subsequent rows must be identity (padding):

```
if r14_t = HALTED: r_k_{t+1} = r_k_t  for all k
```

## boundary constraints

| boundary | register | row | value |
|---|---|---|---|
| input | r3, r4 | 0 | program input operands |
| output | r5 | last active | program output |
| status | r14 | last active | HALTED |
| focus | r7 | last active | 0 (or insufficient for next pattern) |

boundary constraints are point evaluations of the trace polynomial at specific binary coordinates. [[WHIR]] proves these directly as evaluation claims.

## CCS encoding

all constraints map to [[CCS]] instances. the key advantage: high-degree constraints (pattern 15, degree 7) cost only field operations in the [[SuperSpartan]] prover. no cryptographic cost increase over degree-1 constraints.

```
CCS encoding for pattern p:
  M matrices: encode register accesses at rows t and t+1
  S sets: encode which matrices multiply together
  c coefficients: encode addition vs subtraction
  degree: max degree of the constraint polynomial
```

## constraint budget by proof type

| proof type | dominant patterns | total constraints |
|---|---|---|
| identity (preimage) | 15 (one hash) | ~300 |
| anonymous [[cyberlink]] | 15, 4, 9 | ~13,000 |
| delivery (per hop) | 15, 7, 4 | ~60,000 |
| private transfer (BBG) | 15, 7, 9 | ~50,000 |
| recursive verification (jets) | 15, 5, 7, 4 | ~70,000 |
| recursive verification (no jets) | 15 dominates | ~600,000 |

see [[SuperSpartan]] for the IOP that verifies constraints, [[sumcheck]] for the reduction mechanism, [[nox]] for pattern definitions, [[transcript]] for Fiat-Shamir challenge derivation
