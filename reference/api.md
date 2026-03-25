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

the prover/verifier interface and data formats for [[zheng]]. five entry points: prove, verify, fold, decide, fold_row. fold() and decide() are the primary composition interface — HyperNova folding replaces tree aggregation for most use cases.

## prove

```
zheng::prove(
  program:    &NoxProgram,
  input:      &[GoldilocksElement],
  focus:      u64,
  params:     &ProofParams,
) → Result<Proof, ProveError>
```

executes the [[nox]] program with the given input and focus bound. produces the execution trace, encodes it as a multilinear polynomial, runs [[SuperSpartan]] + [[Brakedown]] (or WHIR legacy) to generate a proof.

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

## fold (primary composition)

```
zheng::fold(
  accumulator: &Accumulator,
  instance:    &CCSInstance,
  witness:     &CCSWitness,
) → Result<Accumulator, FoldError>
```

absorbs one proof instance into the running accumulator using [[HyperNova]] folding over [[CCS]]. cost: ~30 field operations + one [[hemera]] hash. this is the primary composition mechanism — preferred over tree aggregation for blocks, epochs, and cross-shard merging.

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
) → Result<Proof, ProveError>
```

produces a final stark proof from the accumulated folds. runs SuperSpartan + sumcheck + Brakedown verification on the folded CCS instance. cost: ~8,000 constraints (Brakedown) / ~70,000 constraints (WHIR legacy). called ONCE at the end of a folding sequence (e.g., end of epoch).

## fold_row (proof-carrying)

```
zheng::fold_row(
  accumulator: &Accumulator,
  trace_row:   &TraceRow,
  prev_row:    &TraceRow,
) → Result<Accumulator, FoldError>
```

folds a single trace row (with its predecessor for transition constraints) into the running accumulator. used for proof-carrying computation — called inside nox reduce() to accumulate the proof during execution. cost: ~30 field operations + 1 hemera hash per row.

sliding-window fold of width 2: each call sees (row_t, row_{t+1}) as one CCS instance, ensuring transition constraints between consecutive rows are checked.

## data types

### Proof

```
Proof {
  commitment:            [u8; 64],
  sumcheck_polynomials:  Vec<Vec<GoldilocksElement>>,
  evaluation_value:      GoldilocksElement,
  pcs_opening:           PCSOpening,    // Brakedown or WHIR, determined by params
}

enum PCSOpening {
  Brakedown(BrakedownProof),   // O(log N + λ) field elements, ~1.3 KiB (recursive)
  WHIR(WHIRProof),             // Merkle paths + folding data, ~154 KiB
}
```

size with Brakedown: ~2 KiB at 128-bit security (sumcheck ~0.5 KiB + evaluation ~0.3 KiB + PCS opening ~1.3 KiB). size with WHIR: ~60 KiB at 100-bit / ~157 KiB at 128-bit. constant regardless of original computation size.

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
  pcs_backend:     PCSBackend,       // Brakedown (default) or WHIR
  jets_enabled:    bool,             // use Layer 2 jets for verification
  max_trace_log:   u32,             // log₂ of maximum trace rows (default: 20)
}

enum PCSBackend {
  Brakedown,   // primary: expander-graph codes, Merkle-free
  WHIR,        // legacy: Reed-Solomon + Merkle
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

### block composition (fold, primary)

```
let mut acc = Accumulator::empty();
for tx in block.transactions() {
  let (instance, witness) = tx.to_ccs();
  acc = zheng::fold(&acc, &instance, &witness)?;  // ~30 field ops each
}
let block_proof = zheng::decide(&acc, &params)?;   // ~8K constraints, once
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

### recursive proof (legacy)

```
let inner_proof = zheng::prove(&computation, &input, focus, &params)?;
let outer_proof = zheng::prove(&verifier_program, &[inner_proof_bytes], verify_focus, &params)?;
```

see [[verifier]] for the verification algorithm, [[transcript]] for Fiat-Shamir construction, [[constraints]] for AIR encoding, [[recursion]] for composition protocol, [[Brakedown]] for the PCS, [[WHIR]] for the legacy PCS