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

each pattern's constraint polynomial C_p(t) = 0 is decomposed into CCS form:

```
Σ_{i ∈ [q]} c_i · ∏_{j ∈ S_i} (M_j · z) = 0
```

where z is the witness vector (the trace row), M_j are sparse matrices that select registers from the trace at row t or t+1, S_i are index sets specifying which M_j outputs multiply together, and c_i are [[Goldilocks field]] coefficients.

register layout for z (row t concatenated with row t+1):

```
z = [r0_t, r1_t, ..., r15_t, r0_{t+1}, r1_{t+1}, ..., r15_{t+1}, 1]
     idx 0   idx 1      idx 15  idx 16     idx 17        idx 31    idx 32
```

index 32 holds the constant 1, used by M matrices that extract a fixed scalar.

## CCS encoding per pattern

### arithmetic patterns (5, 6, 7, 8)

these have the simplest CCS decomposition: one constraint, few matrices.

#### pattern 5: add

polynomial constraint:

```
C_5(t) = r5_{t+1} − r3_t − r4_t = 0
```

CCS decomposition (q = 1 term, degree 1):
- M_0: selects r5_{t+1} (row t+1, register 5 → z index 21)
- M_1: selects r3_t (row t, register 3 → z index 3)
- M_2: selects r4_t (row t, register 4 → z index 4)
- S_0 = {0}, c_0 = 1 — extracts r5_{t+1}
- S_1 = {1}, c_1 = −1 — subtracts r3_t
- S_2 = {2}, c_2 = −1 — subtracts r4_t

```
1·(M_0·z) + (−1)·(M_1·z) + (−1)·(M_2·z) = 0
```

#### pattern 6: sub

polynomial constraint:

```
C_6(t) = r5_{t+1} − r3_t + r4_t = 0
```

CCS decomposition (q = 1 term, degree 1):
- M_0: selects r5_{t+1} (z index 21)
- M_1: selects r3_t (z index 3)
- M_2: selects r4_t (z index 4)
- S_0 = {0}, c_0 = 1
- S_1 = {1}, c_1 = −1
- S_2 = {2}, c_2 = 1

```
1·(M_0·z) + (−1)·(M_1·z) + 1·(M_2·z) = 0
```

#### pattern 7: mul

polynomial constraint:

```
C_7(t) = r5_{t+1} − r3_t × r4_t = 0
```

CCS decomposition (q = 2 terms, degree 2):
- M_0: selects r5_{t+1} (z index 21)
- M_1: selects r3_t (z index 3)
- M_2: selects r4_t (z index 4)
- S_0 = {0}, c_0 = 1 — linear term: r5_{t+1}
- S_1 = {1, 2}, c_1 = −1 — degree-2 term: r3_t × r4_t

```
1·(M_0·z) + (−1)·(M_1·z ⊙ M_2·z) = 0
```

where ⊙ denotes Hadamard (entry-wise) product.

#### pattern 8: inv

polynomial constraint:

```
C_8(t) = r5_{t+1} × r3_t − 1 = 0
```

CCS decomposition (q = 2 terms, degree 2):
- M_0: selects r5_{t+1} (z index 21)
- M_1: selects r3_t (z index 3)
- M_2: selects constant 1 (z index 32)
- S_0 = {0, 1}, c_0 = 1 — degree-2 term: r5_{t+1} × r3_t
- S_1 = {2}, c_1 = −1 — constant term: −1

```
1·(M_0·z ⊙ M_1·z) + (−1)·(M_2·z) = 0
```

### logic patterns (9, 10, 11, 12, 13, 14)

these patterns require bit decomposition. auxiliary registers r8–r13 hold intermediate values (individual bits or partial sums). each bit position generates a sub-constraint, yielding ~64 constraints per pattern invocation.

#### pattern 9: eq

polynomial constraint (two sub-constraints):

```
C_9a(t) = (r3_t − r4_t) × r8_t − r9_t = 0      (r8 = inverse-or-zero, r9 = flag)
C_9b(t) = r5_{t+1} − (1 − r9_t) = 0             (result is 1 when equal)
```

CCS decomposition for C_9a (q = 2 terms, degree 2):
- M_0: selects r3_t (z index 3)
- M_1: selects r4_t (z index 4)
- M_2: selects r8_t (z index 8) — auxiliary: conditional inverse
- M_3: selects r9_t (z index 9) — auxiliary: equality flag
- S_0 = {0, 2}, c_0 = 1 — r3_t × r8_t
- S_1 = {1, 2}, c_1 = −1 — r4_t × r8_t
- S_2 = {3}, c_2 = −1 — −r9_t

the prover sets r9_t = 0 when r3_t = r4_t, and r9_t = 1 otherwise, with r8_t the modular inverse of (r3_t − r4_t) when they differ.

CCS decomposition for C_9b (q = 3 terms, degree 1):
- M_4: selects r5_{t+1} (z index 21)
- M_5: selects constant 1 (z index 32)
- M_6: selects r9_t (z index 9)
- S_3 = {4}, c_3 = 1
- S_4 = {5}, c_4 = −1
- S_5 = {6}, c_5 = 1

```
C_9b: 1·(M_4·z) + (−1)·(M_5·z) + 1·(M_6·z) = 0
```

#### pattern 10: lt

polynomial constraint (range decomposition):

the difference d = r3_t − r4_t is decomposed into 64 bits b_0 … b_63 stored across auxiliary registers (spread over multiple trace rows). two families of sub-constraints:

```
C_10_bit_k: b_k × (b_k − 1) = 0                 (each bit is boolean)
C_10_recompose: r3_t − r4_t − Σ_{k=0}^{63} b_k × 2^k = 0   (bits reconstruct the difference)
```

the result r5_{t+1} = b_63 (the sign bit, indicating r3 < r4 in unsigned interpretation).

CCS decomposition for each bit constraint (q = 2 terms, degree 2):
- M_bit: selects b_k from an auxiliary register
- M_const: selects constant 1 (z index 32)
- S = {bit, bit}, c = 1 — b_k²
- S = {bit}, c = −1 — −b_k

the recomposition constraint is degree 1 with 65 terms (one per bit plus the difference).

#### pattern 11: xor

polynomial constraint (per-bit XOR via arithmetic identity):

r3_t and r4_t are decomposed into bits a_k, b_k. for each bit position k:

```
C_11_bit_k: a_k + b_k − 2 × a_k × b_k − c_k = 0
```

where c_k is the k-th bit of the result. the result is recomposed: r5_{t+1} = Σ c_k × 2^k.

CCS decomposition per bit (q = 4 terms, degree 2):
- M_a: selects a_k, M_b: selects b_k, M_c: selects c_k (from auxiliary registers)
- S_0 = {a}, c_0 = 1 — a_k
- S_1 = {b}, c_1 = 1 — b_k
- S_2 = {a, b}, c_2 = −2 — −2 × a_k × b_k
- S_3 = {c}, c_3 = −1 — −c_k

plus boolean constraints for a_k, b_k, c_k and recomposition constraints for both operands and the result. total: ~64 × 4 sub-constraints.

#### pattern 12: and

polynomial constraint (per-bit AND):

```
C_12_bit_k: a_k × b_k − c_k = 0
```

CCS decomposition per bit (q = 2 terms, degree 2):
- M_a: selects a_k, M_b: selects b_k, M_c: selects c_k
- S_0 = {a, b}, c_0 = 1 — a_k × b_k
- S_1 = {c}, c_1 = −1 — −c_k

plus boolean and recomposition constraints (same structure as pattern 11).

#### pattern 13: not

polynomial constraint (per-bit complement):

```
C_13_bit_k: a_k + c_k − 1 = 0
```

CCS decomposition per bit (q = 3 terms, degree 1):
- M_a: selects a_k, M_c: selects c_k, M_const: selects constant 1
- S_0 = {a}, c_0 = 1
- S_1 = {c}, c_1 = 1
- S_2 = {const}, c_2 = −1

plus boolean and recomposition constraints. all degree 1.

#### pattern 14: shl

polynomial constraint:

```
C_14(t) = r5_{t+1} − r3_t × 2^{r4_t} = 0   (mod 2^64)
```

the shift amount r4_t is decomposed into bits to compute 2^{r4_t} via repeated squaring. auxiliary registers hold intermediate powers. the overflow is handled by range-checking the result to 64 bits.

CCS decomposition: a chain of degree-2 constraints for each bit of the shift amount:

```
C_14_pow_k: pow_{k+1} = pow_k × pow_k × b_k + pow_k × (1 − b_k)
```

simplified: pow_{k+1} = pow_k × (1 + (pow_k − 1) × b_k). each step is degree 2 when b_k is binary. the final constraint multiplies r3_t by the accumulated power and range-checks the result.

### tree patterns (0, 1, 2, 3)

these patterns navigate the subject tree (a binary tree representing the program's data). operand hashes in r1, r2 anchor Merkle-path verification.

#### pattern 0: axis

polynomial constraint:

```
C_0(t) = r1_{t+1} − select(r3_t, r1_t, direction_bit) = 0
```

axis navigates one level in the subject tree. the direction bit (extracted from r3_t, the axis number) determines whether to descend left or right. the constraint enforces that r1_{t+1} (the new operand hash) equals the child hash consistent with the Merkle path:

```
C_0_step: r1_{t+1} − (direction × r8_t + (1 − direction) × r9_t) = 0
```

where r8_t and r9_t hold the left and right child hashes provided by the prover (verified against the parent hash via a separate Poseidon2 check). the direction bit extraction uses one degree-2 constraint per depth level.

CCS decomposition per depth step (q = 3 terms, degree 2):
- M_0: selects r1_{t+1} (z index 17)
- M_1: selects direction bit from auxiliary register
- M_2: selects r8_t (left child hash, z index 8)
- M_3: selects r9_t (right child hash, z index 9)
- M_4: selects constant 1 (z index 32)
- S_0 = {0}, c_0 = 1 — r1_{t+1}
- S_1 = {1, 2}, c_1 = −1 — direction × left_child
- S_2 = {1}, c_2 = 1; combined with S_3 = {3}, c_3 = −1 and S_4 = {4, 3} for the (1 − direction) × right_child term

each depth level of the axis also requires a Poseidon2 hash constraint to verify the parent-child relationship, reusing pattern 15's constraint structure.

#### pattern 1: quote

polynomial constraint:

```
C_1(t) = r5_{t+1} − r3_t = 0
```

the simplest pattern: the result is the literal operand itself.

CCS decomposition (q = 2 terms, degree 1):
- M_0: selects r5_{t+1} (z index 21)
- M_1: selects r3_t (z index 3)
- S_0 = {0}, c_0 = 1
- S_1 = {1}, c_1 = −1

```
1·(M_0·z) + (−1)·(M_1·z) = 0
```

#### pattern 2: compose

polynomial constraint:

compose chains two evaluations: first evaluate sub-expression x, then evaluate sub-expression y using x's output as input. the constraint enforces correct threading of intermediate results:

```
C_2a(t) = r3_{t_mid} − r5_{t_x} = 0     (y's input = x's output)
C_2b(t) = r5_{t+1} − r5_{t_y} = 0       (compose result = y's output)
```

these are degree-1 constraints linking trace rows at three time points (t, t_mid, t_end). the CCS encoding uses M matrices that select registers from the appropriate rows, with the row offsets baked into the matrix structure.

CCS decomposition for each sub-constraint: same shape as pattern 1 (two matrices, degree 1, two terms).

#### pattern 3: cons

polynomial constraint:

cons pairs two sub-results into a new tree node:

```
C_3(t) = r1_{t+1} − poseidon2(r5_{t_left}, r5_{t_right}) = 0
```

the result hash is the Poseidon2 hash of the left and right sub-results. this decomposes into a hash constraint (reusing pattern 15's structure) plus a linking constraint that threads sub-expression outputs:

```
C_3_link_left:  input_left  − r5_{t_left}  = 0
C_3_link_right: input_right − r5_{t_right} = 0
C_3_hash:       r1_{t+1} − hash_output = 0
```

CCS decomposition: the linking constraints are degree 1 (two terms each). the hash constraint follows pattern 15's encoding.

### control patterns (4, 16)

#### pattern 4: branch

polynomial constraint:

```
C_4(t) = r8_t × (r5_{t+1} − r3_t) + (1 − r8_t) × (r5_{t+1} − r4_t) = 0
```

where r8_t is the selector (derived from the condition evaluation): r8_t = 1 selects r3_t (the "yes" branch), r8_t = 0 selects r4_t (the "no" branch).

expanding: r5_{t+1} − r8_t × r3_t − r4_t + r8_t × r4_t = 0

CCS decomposition (q = 4 terms, degree 2):
- M_0: selects r5_{t+1} (z index 21)
- M_1: selects r8_t (z index 8) — selector
- M_2: selects r3_t (z index 3) — yes branch
- M_3: selects r4_t (z index 4) — no branch
- S_0 = {0}, c_0 = 1 — r5_{t+1}
- S_1 = {1, 2}, c_1 = −1 — −selector × yes
- S_2 = {3}, c_2 = −1 — −no
- S_3 = {1, 3}, c_3 = 1 — +selector × no

```
1·(M_0·z) + (−1)·(M_1·z ⊙ M_2·z) + (−1)·(M_3·z) + 1·(M_1·z ⊙ M_3·z) = 0
```

an additional boolean constraint enforces r8_t ∈ {0, 1}:

```
C_4_bool: r8_t × (r8_t − 1) = 0
```

#### pattern 16: hint

polynomial constraint:

hint injects externally computed values into the trace. the constraint structure varies by hint type. the prover supplies a value in r5_{t+1} along with a proof that the external verifier (Layer 1) accepted it. the minimal constraint:

```
C_16(t) = r14_{t+1} − r14_t = 0   (status unchanged through hint)
```

additional constraints depend on the hint category (e.g., Layer 1 state root verification, oracle value attestation). these are encoded as separate CCS instances composed with the main trace via the [[SuperSpartan]] folding mechanism.

CCS decomposition for the base constraint (q = 2 terms, degree 1):
- M_0: selects r14_{t+1} (z index 30)
- M_1: selects r14_t (z index 14)
- S_0 = {0}, c_0 = 1
- S_1 = {1}, c_1 = −1

### hash pattern (15)

#### pattern 15: hash (Poseidon2 round)

polynomial constraint:

Poseidon2 operates on a state of width w (typically 8 field elements). each round applies: S-box (x → x^7), then MDS matrix multiplication, then round constant addition. the state elements are spread across registers r3–r5 and auxiliary registers r8–r13 (six state elements per trace row, requiring two rows per full state).

for a single S-box + MDS step on one state element s:

```
C_15_sbox: r8_t − (s_t)^7 = 0
```

since (s_t)^7 = s_t × s_t × s_t × s_t × s_t × s_t × s_t, the prover decomposes this into intermediate squares:

```
C_15_sq1: r9_t − s_t × s_t = 0                    (s^2)
C_15_sq2: r10_t − r9_t × r9_t = 0                  (s^4)
C_15_cube: r11_t − r10_t × r9_t = 0                (s^6)
C_15_final: r8_t − r11_t × s_t = 0                 (s^7)
```

each sub-constraint is degree 2. this decomposes the degree-7 S-box into four degree-2 constraints per state element.

CCS decomposition for C_15_sq1 (q = 2 terms, degree 2):
- M_0: selects r9_t (z index 9)
- M_1: selects s_t (whichever register holds the state element)
- S_0 = {0}, c_0 = 1
- S_1 = {1, 1}, c_1 = −1 — s_t × s_t (same matrix used twice in the product set)

the remaining sub-constraints follow the same shape: one degree-2 product term and one degree-1 extraction term.

the MDS matrix multiplication is a linear operation, encoded as a single degree-1 constraint per output element:

```
C_15_mds_j: state_j_{t+1} − Σ_{k} MDS[j][k] × sbox_output_k = 0
```

CCS decomposition for MDS (q = w+1 terms, degree 1):
- one M matrix per sbox output element, with the MDS coefficient baked into c
- S_k = {k}, c_k = MDS[j][k] for each input k
- S_{w} = {out_j}, c_{w} = −1 for the output element

round constants are added by adjusting the c coefficient of the constant-1 wire (z index 32).

total per Poseidon2 round: 4 × w degree-2 constraints (S-box decomposition) + w degree-1 constraints (MDS). for w = 8: 32 + 8 = 40 constraints per round. a full Poseidon2 permutation with 8 rounds uses ~320 constraints.

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
