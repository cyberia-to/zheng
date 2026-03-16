---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: zheng API, prover API, verifier API
---
# api

the prover/verifier interface and data formats for [[zheng]]. three entry points: prove, verify, fold.

## prove

```
zheng::prove(
  program:    &NoxProgram,
  input:      &[GoldilocksElement],
  focus:      u64,
  params:     &ProofParams,
) → Result<Proof, ProveError>
```

executes the [[nox]] program with the given input and focus bound. produces the execution trace, encodes it as a multilinear polynomial, runs [[SuperSpartan]] + [[WHIR]] to generate a proof.

| parameter | type | description |
|---|---|---|
| program | NoxProgram | compiled nox program (pattern sequence) |
| input | [GoldilocksElement] | public input values for registers r3, r4 at row 0 |
| focus | u64 | maximum focus budget for execution |
| params | ProofParams | security level, jet configuration |

returns:
- `Proof` on success: commitment, sumcheck polynomials, evaluation, WHIR opening
- `ProveError::ExecutionFailed` if nox halts with error
- `ProveError::FocusExhausted` if computation exceeds focus bound
- `ProveError::TraceOverflow` if trace exceeds maximum rows (2^32)

## verify

```
zheng::verify(
  proof:      &Proof,
  statement:  &Statement,
  params:     &ProofParams,
) → Result<(), VerifyError>
```

checks the proof against the public statement. pure computation: field arithmetic + [[hemera]] hashes. no access to the original trace or witness.

| parameter | type | description |
|---|---|---|
| proof | Proof | the proof to verify |
| statement | Statement | program hash, input/output hashes, focus bound |
| params | ProofParams | must match prover's params |

returns:
- `Ok(())` on valid proof
- `VerifyError::SumcheckFailed(round)` if sumcheck consistency check fails
- `VerifyError::EvaluationMismatch` if claimed evaluation disagrees with constraints
- `VerifyError::WHIRFailed` if WHIR opening verification rejects

## fold

```
zheng::fold(
  accumulator: &Accumulator,
  instance:    &CCSInstance,
  witness:     &CCSWitness,
) → Result<Accumulator, FoldError>
```

absorbs one proof instance into the running accumulator using [[HyperNova]] folding over [[CCS]]. cost: O(1) field operations + one [[hemera]] hash.

| parameter | type | description |
|---|---|---|
| accumulator | Accumulator | running folded state (or Accumulator::empty() for first fold) |
| instance | CCSInstance | the CCS instance from a proof |
| witness | CCSWitness | the CCS witness from a proof |

```
zheng::decide(
  accumulator: &Accumulator,
  params:      &ProofParams,
) → Result<Proof, ProveError>
```

produces a final stark proof from the accumulated folds. this is the expensive step (~70,000 constraints). called once at the end of a folding sequence (e.g., end of epoch).

## data types

### Proof

```
Proof {
  commitment:            [u8; 64],
  sumcheck_polynomials:  Vec<Vec<GoldilocksElement>>,
  evaluation_value:      GoldilocksElement,
  whir_opening:          WHIRProof,
}
```

size: ~60 KiB at 100-bit security, ~157 KiB at 128-bit security. constant regardless of original computation size.

### Statement

```
Statement {
  program_hash:  [u8; 64],       // hemera hash of the nox program
  input_hash:    [u8; 64],       // hemera hash of public inputs
  output_hash:   [u8; 64],       // hemera hash of public outputs
  focus_bound:   u64,            // maximum focus consumed
}
```

### ProofParams

```
ProofParams {
  security_level:  SecurityLevel,    // Sec100 or Sec128
  jets_enabled:    bool,             // use Layer 2 jets for verification
  max_trace_log:   u32,             // log₂ of maximum trace rows (default: 20)
}
```

### Accumulator

```
Accumulator {
  committed_instance:  CCSInstance,
  witness_commitment:  [u8; 64],
  error_term:          GoldilocksElement,
  step_count:          u64,
}
```

## usage patterns

### single proof

```
let proof = zheng::prove(&program, &input, focus, &params)?;
zheng::verify(&proof, &statement, &params)?;
```

### recursive proof

```
let inner_proof = zheng::prove(&computation, &input, focus, &params)?;
let outer_proof = zheng::prove(&verifier_program, &[inner_proof_bytes], verify_focus, &params)?;
```

### epoch folding

```
let mut acc = Accumulator::empty();
for block in epoch.blocks() {
  for tx in block.transactions() {
    let (instance, witness) = tx.to_ccs();
    acc = zheng::fold(&acc, &instance, &witness)?;
  }
}
let epoch_proof = zheng::decide(&acc, &params)?;
```

see [[verifier]] for the verification algorithm, [[transcript]] for Fiat-Shamir construction, [[constraints]] for AIR encoding, [[recursion-spec]] for composition protocol, [[WHIR]] for the PCS
