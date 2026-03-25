---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: zheng API, prover API, verifier API
diffusion: 0.00010722364868599256
springs: 0.0004532788515682401
heat: 0.000350448841959531
focus: 0.00025968524820537114
gravity: 0
density: 0.65
---
# api

five entry points: **commit**, **open**, **verify**, **fold**, **decide**.

## commit

```
zheng::commit(
  program:    &NoxProgram,
  input:      &[GoldilocksElement],
  focus:      u64,
  params:     &ProofParams,
) -> Result<(Proof, Accumulator), CommitError>
```

executes the [[nox]] program with the given input and focus bound. produces the execution trace, encodes it as a multilinear polynomial, commits via [[Brakedown]], runs [[SuperSpartan]] sumcheck. returns a proof and an accumulator ready for folding.

| parameter | type | description |
|---|---|---|
| program | NoxProgram | compiled nox program (pattern sequence) |
| input | [GoldilocksElement] | public input values for registers r3, r4 at row 0 |
| focus | u64 | maximum focus budget for execution |
| params | ProofParams | security level, PCS configuration |

returns:
- `(Proof, Accumulator)` on success
- `CommitError::ExecutionFailed` if nox halts with error
- `CommitError::FocusExhausted` if computation exceeds focus bound
- `CommitError::TraceOverflow` if trace exceeds maximum rows (2^32)

## open

```
zheng::open(
  proof:      &Proof,
  point:      &[GoldilocksElement],
  params:     &ProofParams,
) -> Result<Opening, OpenError>
```

produces a Brakedown opening at the sumcheck output point. the opening proves that the committed polynomial evaluates to the claimed value at the given point. recursive Brakedown: O(log N + lambda) proof size via log log N levels of self-commitment.

## verify

```
zheng::verify(
  proof:      &Proof,
  statement:  &Statement,
  params:     &ProofParams,
) -> Result<(), VerifyError>
```

checks the proof against the public statement. pure computation: field arithmetic + ~3 [[hemera]] calls. no access to the original trace or witness.

| parameter | type | description |
|---|---|---|
| proof | Proof | the proof to verify |
| statement | Statement | program hash, input/output hashes, focus bound |
| params | ProofParams | must match prover's params |

returns:
- `Ok(())` on valid proof
- `VerifyError::SumcheckFailed(round)` if sumcheck consistency check fails
- `VerifyError::EvaluationMismatch` if claimed evaluation disagrees with constraints
- `VerifyError::PCSFailed` if Brakedown opening verification rejects

## fold

```
zheng::fold(
  accumulator: &Accumulator,
  instance:    &CCSInstance,
  witness:     &CCSWitness,
) -> Result<Accumulator, FoldError>
```

absorbs one proof instance into the running accumulator using [[HyperNova]] folding over [[CCS]]. cost: ~30 field operations + one [[hemera]] hash. the primary composition mechanism — preferred for blocks, epochs, and cross-shard merging.

| parameter | type | description |
|---|---|---|
| accumulator | Accumulator | running folded state (or Accumulator::empty() for first fold) |
| instance | CCSInstance | the CCS instance from a proof |
| witness | CCSWitness | the CCS witness from a proof |

## decide

```
zheng::decide(
  accumulator: &Accumulator,
  params:      &ProofParams,
) -> Result<Proof, DecideError>
```

produces a final proof from the accumulated folds. runs SuperSpartan + sumcheck + Brakedown verification on the folded CCS instance. cost: ~825 constraints (CCS jet + batch + algebraic FS). called once at the end of a folding sequence.

## data types

### Proof

```
Proof {
  commitment:            [u8; 64],
  sumcheck_polynomials:  Vec<Vec<GoldilocksElement>>,
  evaluation_value:      GoldilocksElement,
  pcs_opening:           BrakedownProof,
}
```

size: ~2 KiB at 128-bit security (sumcheck ~0.5 KiB + evaluation ~0.3 KiB + PCS opening ~1.3 KiB). constant regardless of original computation size.

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
  pcs_backend:     PCSBackend,       // Brakedown (default) or Binius
  max_trace_log:   u32,             // log_2 of maximum trace rows (default: 20)
}

enum PCSBackend {
  Brakedown,   // primary: expander-graph codes, Merkle-free (Goldilocks)
  Binius,      // binary: F_2 tower (2 of 14 nox languages)
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
let (proof, _) = zheng::commit(&program, &input, focus, &params)?;
zheng::verify(&proof, &statement, &params)?;
```

### block composition (fold)

```
let mut acc = Accumulator::empty();
for tx in block.transactions() {
  let (instance, witness) = tx.to_ccs();
  acc = zheng::fold(&acc, &instance, &witness)?;  // ~30 field ops each
}
let block_proof = zheng::decide(&acc, &params)?;   // ~825 constraints, once
```

### epoch composition (fold)

```
let mut acc = Accumulator::empty();
for block in epoch.blocks() {
  for tx in block.transactions() {
    let (instance, witness) = tx.to_ccs();
    acc = zheng::fold(&acc, &instance, &witness)?;
  }
}
let epoch_proof = zheng::decide(&acc, &params)?;   // one decider for entire epoch
```

### proof-carrying computation

```
let mut acc = Accumulator::empty();
let mut state = initial_state;
for step in computation.steps() {
  let (result, trace_row) = nox::reduce(&state, &step);
  acc = zheng::fold_row(&acc, &trace_row, &prev_row)?;  // ~30 ops per step
  prev_row = trace_row;
  state = result;
}
// proof is ready — no separate proving phase
let proof = zheng::decide(&acc, &params)?;
```

see [[verifier]] for the verification algorithm, [[transcript]] for Fiat-Shamir construction, [[constraints]] for AIR encoding, [[recursion]] for composition protocol, [[Brakedown]] for the PCS
