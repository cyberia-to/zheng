---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: zheng API, prover API, verifier API
---
# api

five entry points: **commit**, **open**, **verify**, **fold**, **decide**.

## execution model (two phases)

zheng proofs require two separate steps:

**phase 1 — execution (nox):** run the computation and collect the trace.

```rust
use nox::{reduce, Order, NounId, NullCalls, VecTrace};

let mut order = Order::<65536>::new();
// ... build object and formula nouns ...
let mut tracer = VecTrace::default();
let outcome = reduce(&mut order, object, formula, budget, &NullCalls, &mut tracer);
// tracer.0 now contains one TraceRow per reduce() call
```

**phase 2 — proving (zheng):** encode the trace and produce a proof.

```rust
let proof = zheng::commit(&tracer, &hash_aux, &axis_openings, &look_openings, &statement, &params)?;
```

nox produces the trace; zheng consumes it. the two phases are independent — run nox with any `CallProvider`, pass the resulting `&[TraceRow]` to zheng.

## commit

```
zheng::commit(
  trace:          &nox::VecTrace,
  hash_aux:       &[HashAux],        one per Poseidon2 hash block (the sponge rate)
  axis_openings:  &[AxisOpening],    one per prover-active axis row
  look_openings:  &[LookOpening],    one per look row
  statement:      &Statement,
  params:         &ProofParams,
) -> Result<TraceProof, CommitError>
```

turns every consecutive trace pair into a witness of the universal step instance ([[constraints]]), appends the replayed Fiat-Shamir Poseidon2 rounds of each opening and the BBG root chain as further universal rows, folds them all into ONE [[HyperNova]] accumulator, folds the opening bindings (degree-1 eq steps) into a second accumulator when there are any, and closes each with one [[decider]] under a shared linkage digest.

returns:
- `TraceProof { universal, binding: Option<_> }` on success — two groups at most, ~4 KiB, independent of trace length
- `CommitError::FocusExhausted` if the trace exceeds the statement's focus bound
- `CommitError::StatementMismatch` if input_hash/output_hash do not bind the first/last rows
- `CommitError::StepUnsatisfied(t)` if trace pair t violates its pattern's constraint, carries an unknown tag or an out-of-range hash round — commit refuses to prove what the verifier could not see through the relaxed fold
- `CommitError::HashBinding` / `AxisBinding` / `LookBinding` if an opening does not bind to the trace
- `CommitError::TraceOverflow` if openings/hints do not match the trace or the trace has fewer than two rows

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
- `VerifyError::LensFailed` if Brakedown opening verification rejects

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
  commitment:            [u8; 32],
  sumcheck_polynomials:  Vec<Vec<GoldilocksElement>>,
  evaluation_value:      GoldilocksElement,
  pcs_opening:           BrakedownProof,
}
```

size: ~2 KiB at 128-bit security (sumcheck ~0.5 KiB + evaluation ~0.3 KiB + Lens opening ~1.3 KiB). constant regardless of original computation size.

### Statement

```
Statement {
  program_hash:  [u8; 32],       // hemera hash of the nox program
  input_hash:    [u8; 32],       // hemera hash of public inputs
  output_hash:   [u8; 32],       // hemera hash of public outputs
  focus_bound:   u64,            // maximum focus consumed
}
```

### ProofParams

```
ProofParams {
  security_level:  SecurityLevel,    // Sec100 or Sec128
  lens_backend:    LensBackend,      // Brakedown (default) or Binius
  max_trace_log:   u32,             // log_2 of maximum trace rows (default: 20)
}

enum LensBackend {
  Brakedown,   // primary: expander-graph codes, Merkle-free (Goldilocks)
  Binius,      // binary: F_2 tower (2 of 14 nox languages)
}
```

### Accumulator

```
Accumulator {
  committed_instance:  CCSInstance,     prover state, never on the wire
  witness_commitment:  [u8; 32],
  error_evals:         [GoldilocksElement; m]   one per constraint row
  step_count:          u64,
}
```

### TraceProof

```
TraceProof {
  universal:  ProofGroup,               every Layer-1 row, instance = universal_ccs()
  binding:    Option<ProofGroup>,       opening bindings, instance = eq_instance()
}
ProofGroup { proof: Proof, accumulator: Accumulator }
```

the verifier derives each group's instance from its position; a proof never names its own instance.

## usage patterns

### single proof

```
let proof = zheng::commit(&trace, &hash_aux, &[], &[], &statement, &params)?;
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

see [[verifier]] for the verification algorithm, [[transcript]] for Fiat-Shamir construction, [[constraints]] for AIR encoding, [[recursion]] for composition protocol, [[lens]] for polynomial commitment

### authenticated PCS wire format

With `serde`, the decider PCS opening is the complete Lens `TensorMerkle`
variant. Serialization retains the row combination and every queried column,
index, and Merkle authentication path. Deserialization rejects legacy `Tensor`
and other PCS variants. Artifacts using the former indices-only encoding must
be regenerated; dropping authenticated column data is forbidden.
