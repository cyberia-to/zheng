# trace to proof

the concrete journey from [[nox]] execution to zheng proof. this article bridges the VM and the proof system, showing exactly how computation becomes cryptographic evidence.

## the execution trace

when [[nox]] runs a program, it produces a table. each row is one reduction step — one application of a pattern to the current term. the table has 16 columns (registers), indexed 0 through 15:

```
register  name            role
────────────────────────────────────────────────────
r0        pattern         which of the 16 patterns fired
r1        object_hash     hash of the object being reduced
r2        formula_hash    hash of the formula being applied
r3        operand_a       first operand
r4        operand_b       second operand
r5        result          output of this reduction step
r6        focus_before    focus counter at entry
r7        focus_after     focus counter at exit
r8        type_tag_a      type of operand_a
r9        type_tag_b      type of operand_b
r10       type_tag_out    type of result
r11       aux_0           auxiliary register (pattern-specific)
r12       aux_1           auxiliary register (pattern-specific)
r13       aux_2           auxiliary register (pattern-specific)
r14       status          step status (running / halted / error)
r15       step_index      position in the trace
```

all values are elements of the [[Goldilocks field]] (p = 2^64 - 2^32 + 1). a trace with 1,000 reduction steps is a 1,000 × 16 table of field elements.

## padding to power of two

the [[sumcheck protocol]] operates over the boolean hypercube {0,1}^n, which has 2^n points. the trace must therefore have exactly 2^n rows. if the raw trace has 1,000 rows, it is padded to 1,024 (2^10).

padding rows replicate the final halted state. the pattern register is set to the halted pattern, and all other registers copy the last valid row's values. these padding rows satisfy the AIR constraints trivially: the halted pattern's transition constraint is the identity (every register stays unchanged).

## multilinear encoding

the padded trace (2^n rows × 2^4 columns) becomes a single multilinear polynomial f over n + 4 boolean variables. the encoding works by address:

- variables x₁ through x_n encode the row index in binary
- variables x_{n+1} through x_{n+4} encode the column index in binary

for any binary assignment (b₁, ..., b_n, c₁, ..., c₄):

```
f(b₁, ..., b_n, c₁, ..., c₄) = trace[row(b₁...b_n)][col(c₁...c₄)]
```

the polynomial f is the unique multilinear extension of this table. it agrees with the trace on all 2^{n+4} binary inputs and interpolates smoothly over the full [[Goldilocks field]]. this is the polynomial that Brakedown commits to.

## AIR constraints from nox patterns

each of [[nox]]'s 16 patterns contributes a transition constraint — a polynomial equation that must hold between consecutive rows.

## full constraint table

```
PATTERN → CONSTRAINT                                        │ DEGREE │ CONSTRAINTS
────────────────────────────────────────────────────────────┼────────┼────────────
0  axis     navigation through subject tree                │ 1      │ ~depth
1  quote    output = literal constant                       │ 1      │ 1
2  compose  chain: eval x, eval y, eval result on x's output│ 1      │ 2
3  cons     pair two sub-results                            │ 1      │ 2
4  branch   selector × (next − yes) + (1−sel) × (next − no)│ 2      │ 2
5  add      out = a + b mod p                               │ 1      │ 1
6  sub      out = a − b mod p                               │ 1      │ 1
7  mul      out = a × b mod p                               │ 2      │ 1
8  inv      out × input = 1 mod p (Fermat verification)    │ 2      │ 1
9  eq       (a − b) × inv = (a ≠ b), out = 1 − (a ≠ b)    │ 2      │ 1
10 lt       range decomposition into bits                   │ 1      │ ~64
11 xor      bit decomposition + XOR per bit                 │ 2      │ ~64
12 and      bit decomposition + AND per bit                 │ 2      │ ~64
13 not      bitwise complement                              │ 1      │ ~64
14 shl      shift via multiplication by 2^n                 │ 2      │ ~64
15 hash     Poseidon2 round function across rows            │ 7      │ ~736
16 hint     constraint check (Layer 1 verification)         │ varies │ varies
```

[[SuperSpartan]] handles AIR constraints of any degree via [[CCS]]. high-degree constraints (pattern 15: degree 7) cost only field operations in the prover — no cryptographic cost increase over degree-1 constraints. this is the [[CCS]] advantage: the Poseidon2 rounds inside the hash pattern are free in the IOP layer.

three examples spanning different degrees follow.

# pattern 5: add (degree 1)

when r0_t = 5 (the add pattern fires at row t), the result at the next row must be the sum of the operands:

```
r5_{t+1} = r3_t + r4_t
```

this is a degree-1 constraint: a linear relation among register values at adjacent rows. the constraint polynomial is C₅(t) = r5_{t+1} - r3_t - r4_t, which equals zero on every row where pattern 5 fires.

# pattern 7: mul (degree 2)

when r0_t = 7 (multiply), the result is the product:

```
r5_{t+1} = r3_t × r4_t
```

the constraint polynomial C₇(t) = r5_{t+1} - r3_t × r4_t is degree 2. the multiplication of two register values introduces one degree of non-linearity.

# pattern 15: hash (degree 7)

when r0_t = 15, the row encodes one round of [[hemera]] (Poseidon2). the Poseidon2 round function applies the S-box x^7 to the state, then a linear layer. the constraint spans consecutive rows — the state after applying x^7 and the MDS matrix at row t must equal the state at row t+1.

```
state_{t+1} = MDS × (state_t)^7
```

the degree-7 S-box makes this a degree-7 transition constraint. in classical STARKs this would cause a 7x blowup in the quotient polynomial. in [[SuperSpartan]], it costs a few extra field operations per [[sumcheck]] round — no cryptographic penalty.

## boundary constraints

transition constraints govern consecutive rows. boundary constraints pin specific rows to known values.

the input boundary fixes row 0: the initial registers must match the program's input. if the computation adds 3 and 5, then r3_0 = 3 and r4_0 = 5.

the output boundary fixes the last active row: the result register must contain the program's output, and the status register must indicate clean halting.

boundary constraints are point evaluations. they assert that f, evaluated at specific binary coordinates, equals specific field elements. Brakedown proves these directly as evaluation claims.

## the combined constraint polynomial

the 16 pattern constraints must be combined into a single polynomial. the pattern selector handles this: at each row, only one pattern is active (the value in r0). the combined constraint is:

```
C(t) = Σ_{p=0}^{15} selector_p(r0_t) × C_p(t)
```

where selector_p(r0_t) equals 1 when r0_t = p and 0 otherwise. the selector is a polynomial in r0_t constructed via Lagrange interpolation over the 16 pattern values.

if the trace is valid — every pattern was executed correctly — then C(t) = 0 for every row t. the [[sumcheck protocol]] verifies this: the sum of C over all 2^n rows equals zero. [[SuperSpartan]] orchestrates this sumcheck, reducing the exponential sum to a single evaluation point, which Brakedown opens.

## focus accounting

every [[nox]] computation has a focus budget. focus is the resource that bounds computation — the analog of gas in other VMs, but deterministic and exact.

each row enforces the focus transition:

```
r7_t = r6_t - cost(r0_t)
```

focus_after equals focus_before minus the cost of the pattern that fired. the cost function is fixed per pattern: arithmetic patterns cost 1, hash rounds cost more. this constraint is part of every pattern's AIR — it is enforced universally, regardless of which pattern fires.

when focus reaches zero, the status register transitions to halted and the computation ends cleanly. the boundary constraint on the last row checks that r14 (status) indicates halted and r7 (focus_after) is zero or that r6 (focus_before) was insufficient for the next pattern's cost.

## a concrete example

consider a simple program: add 3 and 5. [[nox]] executes this in one reduction step (plus padding). with initial focus of 10:

```
row  r0   r3   r4   r5   r6    r7   r14     description
───────────────────────────────────────────────────────
  0   5    3    5    0    10    9    run     add: r5 ← r3 + r4
  1   0    3    5    8     9    9    halt    result in r5, halted
```

the AIR constraint for row 0: r0 = 5 (add pattern), so C₅ applies. check: r5₁ = 8 = 3 + 5 = r3₀ + r4₀. the constraint is satisfied. focus: r7₀ = 9 = 10 - 1 = r6₀ - cost(5). satisfied.

this 2-row trace is padded to 2^1 = 2 rows (already a power of two). the multilinear polynomial f has 1 + 4 = 5 variables. Brakedown commits to f. [[SuperSpartan]] runs the sumcheck over 2 rows. the verifier checks the sumcheck transcript and one Brakedown evaluation proof. the entire proof attests that 3 + 5 = 8 — with cryptographic certainty, without revealing the trace.

## from trace to trust

the pipeline recapitulates:

```
nox program → execution → trace table (2^n × 16)
    → pad to power of two
    → encode as multilinear polynomial f
    → Brakedown_commit(f) → commitment C
    → SuperSpartan sumcheck over AIR constraints → point r
    → Brakedown_open(f, r) → proof π
    → verifier checks transcript + evaluation proof
```

the trace is the witness. the polynomial is its algebraic encoding. the commitment binds the prover. the sumcheck verifies the constraints. the evaluation proof closes the loop. what enters as computation exits as evidence.

## references

- see [[whirlaway]] for the historical architecture
- see [[superspartan]] for the IOP that verifies constraints
- see [[nox]] for the VM specification and pattern definitions
- see [[hemera]] for the Poseidon2 hash used in pattern 15 and in Brakedown commitments
