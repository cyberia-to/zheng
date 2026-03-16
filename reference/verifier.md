---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: zheng verifier, stark verifier
---
# verifier

the standalone verifier algorithm for [[zheng]]. accepts a proof and a public statement, returns accept or reject. the verifier is a [[nox]] program — it runs inside the same VM that produced the original trace, enabling recursive proof composition.

## algorithm

```
VERIFY(commitment C, statement S, proof π) → accept/reject:

  1. INIT TRANSCRIPT
     T = transcript_init(DOMAIN_SEP)
     T.absorb(S)
     T.absorb(C)

  2. SUMCHECK VERIFICATION (k rounds, k = n + 4)
     claim₀ = 0  (constraints must sum to zero)
     for i in 1..k:
       gᵢ = π.sumcheck_polynomials[i]
       assert gᵢ(0) + gᵢ(1) = claim_{i-1}
       T.absorb(gᵢ)
       rᵢ = T.squeeze()
       claimᵢ = gᵢ(rᵢ)

  3. EVALUATION CHECK
     r = (r₁, ..., r_k)
     v = π.evaluation_value
     assert claimₖ = constraint_eval(v, r, S)

  4. WHIR VERIFICATION
     assert WHIR_verify(C, r, v, π.whir_opening)

  return accept
```

step 2 is pure field arithmetic. step 4 is hash operations (Merkle path verification). the split determines the cost structure.

## constraint evaluation

step 3 checks that the sumcheck's final claim equals `constraint_eval(v, r, S)`. this function reconstructs the constraint polynomial's evaluation at the random point r chosen during sumcheck, using the prover-supplied register evaluation v.

### register layout

the trace table has 16 registers per row:

| register | meaning |
|---|---|
| r0 | pattern tag (which of the 17 nox patterns this row executes) |
| r1, r2 | operand hashes (left, right) |
| r3, r4 | inputs (immediate values or dereferenced operands) |
| r5 | result |
| r6 | focus_before (focus counter entering this step) |
| r7 | focus_after (focus counter leaving this step) |
| r8–r13 | auxiliary (pattern-specific intermediate values) |
| r14 | status (0 = running, 1 = halted, 2 = error) |
| r15 | step (row index, starting from 0) |

the prover commits to the multilinear extension of each register column. `v` is the vector of all 16 register evaluations at the random point r: `v[j] = f_j(r)` where `f_j` is the multilinear extension of register column j over the boolean hypercube.

### selector polynomials

each pattern p ∈ {0, 1, ..., 16} has a Lagrange selector polynomial:

```
selector_p(x) = Π_{q ≠ p} (x - q) / (p - q)
```

evaluated at `v[0]` (the pattern tag register at point r), `selector_p(v[0])` is 1 when the pattern tag equals p and 0 otherwise. this demultiplexes the single constraint evaluation into the correct pattern.

### pattern constraints

each pattern p defines a constraint polynomial `C_p` over the register values. for example:

- pattern 5 (add): `C_5(v) = v[3] + v[4] - v[5]` (inputs sum to result)
- pattern 7 (mul): `C_7(v) = v[3] × v[4] - v[5]` (inputs multiply to result)
- pattern 8 (inv): `C_8(v) = v[3] × v[5] - 1` (input times result is one)
- pattern 15 (hash): `C_15(v) = hemera(v[3], v[4]) - v[5]` (hash of inputs equals result)

all 17 patterns contribute, but the selector zeroes out every pattern except the active one.

### the formula

```
constraint_eval(v, r, S) = eq(r_row, r) × Σ_{p=0}^{16} selector_p(v[0]) × C_p(v)
```

where:

- `r_row` is the row-dimension component of r (the first n variables, where 2^n is the number of trace rows)
- `eq(r_row, r)` is the multilinear equality polynomial: `eq(a, b) = Π_i (a_i × b_i + (1 - a_i)(1 - b_i))`, which ties the sumcheck reduction to the specific evaluation point
- the sum over p combines all 17 pattern constraints, weighted by selectors
- `C_p(v)` evaluates pattern p's constraint using the register values at r

the sumcheck protocol reduces the claim "the constraint polynomial sums to zero over the boolean hypercube" to a single evaluation at a random point. `constraint_eval` computes that single evaluation. if the prover is honest, every row satisfies its pattern constraint, the sum is zero, and this evaluation matches `claimₖ`.

### boundary constraints

boundary constraints enforce the public statement S at specific trace positions. these are point evaluations at binary coordinates (vertices of the hypercube):

- at row 0: `f_14(0, 0, ..., 0) = 0` (status is running), `f_15(0, 0, ..., 0) = 0` (step counter starts at zero)
- at the final row: `f_14(1, 1, ..., 1) = 1` (status is halted)
- program hash: the commitment to the opcode column must match `S.program_hash`
- input/output: `f_3(0, ..., 0) = S.input_hash` and `f_5(last_row) = S.output_hash`
- focus bound: `f_6(0, ..., 0) - f_7(last_row) ≤ S.focus_bound`

boundary constraints are folded into the same sumcheck by adding them as additional terms with their own random combiners (drawn from the transcript). at the evaluation point r, the verifier checks these using the same register evaluations v: since multilinear extensions are unique, `f_j(binary_point)` can be reconstructed from `f_j(r)` via the commitment (WHIR opening at the binary coordinate), or the prover supplies these boundary evaluations separately and the verifier includes them in the WHIR batch check of step 4.

### relationship to sumcheck

the sumcheck protocol (step 2) starts with `claim₀ = 0` because a valid trace satisfies all constraints on every row, so the constraint polynomial sums to zero over the hypercube. after k rounds of interaction, the verifier holds a random point r and a final claim `claimₖ`. step 3 asserts `claimₖ = constraint_eval(v, r, S)`: the reduced claim equals the actual constraint evaluation at r. step 4 then verifies (via WHIR) that v is the correct evaluation of the committed polynomials at r. together, steps 3 and 4 complete the sumcheck verification — step 3 checks algebraic consistency, step 4 checks that the prover did not lie about v.

## cost breakdown

| component | without jets | with jets | reduction |
|---|---|---|---|
| parse proof | ~1,000 | ~1,000 | 1× |
| Fiat-Shamir challenges | ~30,000 | ~5,000 | 6× |
| Merkle verification | ~500,000 | ~50,000 | 10× |
| constraint evaluation | ~10,000 | ~3,000 | 3× |
| WHIR verification | ~50,000 | ~10,000 | 5× |
| total | ~600,000 | ~70,000 | 8.5× |

Merkle verification dominates without jets (83%). the merkle_verify jet reduces it 10×. this single jet makes recursion practical.

## nox pattern decomposition

every verifier operation maps to native [[nox]] patterns:

| verifier operation | nox patterns | why native |
|---|---|---|
| field arithmetic | 5 (add), 6 (sub), 7 (mul), 8 (inv) | [[Goldilocks field]] is the native field |
| hash computation | 15 (hash) / hash jet | [[hemera]] is the nox hash |
| [[sumcheck]] verification | 5, 7, 9 | pure field arithmetic |
| [[WHIR]] opening verification | 15, 4, poly_eval/merkle_verify/fri_fold jets | Merkle paths + polynomial eval |

no external primitive enters the verification loop. the verifier is closed under the nox instruction set. consequence: verify(proof) can itself be proven, and verify(verify(proof)) too, to arbitrary depth.

## input/output format

```
INPUTS (public):
  commitment:  [u8; 64]              // hemera digest
  statement:   Statement {
    program_hash: [u8; 64],           // hash of the nox program
    input_hash:   [u8; 64],           // hash of public inputs
    output_hash:  [u8; 64],           // hash of public outputs
    focus_bound:  u64,                // maximum focus consumed
  }

PROOF:
  sumcheck_polynomials: Vec<Vec<GoldilocksElement>>,
  evaluation_value:     GoldilocksElement,
  whir_opening:         WHIRProof,

OUTPUT:
  accept / reject
```

## verification time

| security level | verification time | operations |
|---|---|---|
| 100-bit | ~290 μs | ~1,800 hemera hashes + field ops |
| 128-bit | ~1.0 ms | ~2,700 hemera hashes + field ops |

verification time is independent of the original computation size. a proof of a 300-constraint identity check and a proof of a million-constraint neural network inference verify in the same time.

## recursive verification

when the verifier runs as a nox program, its execution trace can be proven by zheng. the recursive proof attests that a previous proof was valid.

```
proof_A = zheng.prove(computation)         // ~|C| constraints
proof_B = zheng.prove(zheng.verify(proof_A))  // ~70K constraints (with jets)
proof_C = zheng.prove(zheng.verify(proof_B))  // ~70K constraints (with jets)
```

each recursion level costs exactly ~70,000 constraints with jets, regardless of the original computation size. proof size remains constant: ~60-157 KiB.

see [[transcript]] for Fiat-Shamir construction, [[sumcheck]] for the core protocol, [[WHIR]] for the opening verification, [[constraints]] for the AIR format, [[nox]] for the VM
