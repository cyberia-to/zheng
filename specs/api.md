---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: zheng API, prover API, verifier API
---
# api

the public API proves and verifies nox executions. the prover runs the program itself; the verifier recompiles the relation from the statement and never runs nox. every proof can travel as one `ZHENGPF1` envelope. protocols: [[execution]]; bounds: [[soundness]].

## public certificate v3 (envelope profile 0)

```rust
use zheng::execution::{certify_execution, verify_certificate, verify_certificate_with};

let (statement, certificate) = certify_execution(&program, &input, budget)?;
verify_certificate(&statement, &certificate)?;              // recompiles the CCS
verify_certificate_with(&statement, &certificate, &vk)?;    // cached verifying key
```

`ExecutionStatement`: flat canonical program, public input atoms, output atoms, reduction count, budget. `Certificate`: the free witness positions in index order. exact check, error 0 for the compiled relation; linear size, witness disclosed.

## state-public v3 (envelope profile 3)

```rust
use zheng::execution::state::certify_state_execution;

let (statement, certificate) =
    certify_state_execution(&program, &input, budget, root_in_subject, &evidence)?;
statement.verify_certificate(&certificate, &evidence)?;
```

`StateStatement` adds the state root, the root-in-subject flag and one `PublicLookup` per read site. the verifier authenticates `StateEvidence` under the statement's own root before pinning any read.

## succinct (envelope profile 1)

```rust
use zheng::execution::succinct;

let (statement, proof) = succinct::prove_default(&program, &input, budget)?;   // WHIR, shipped parameters
let (statement, proof) = succinct::prove::<P>(&params, &program, &input, budget)?;
succinct::verify::<P>(&statement, &proof)?;
succinct::verify_with::<P>(&statement, &proof, Some(&vk))?;
succinct::prove_state::<P>(&params, &program, &input, budget, root_in_subject, &evidence)?;
succinct::verify_state::<P>(&statement, &proof, &evidence)?;
```

`P: SuccinctPcs` is the lens PCS (`Whir`, id 1 — shipped; `TensorRs`, id 2). `succinct::params_for` gives the shipped WHIR parameters (rate 1/64, folding factor 4, 24 grinding bits). `succinct::admit` rejects any parameter set lens proves below 128 bits. measured: hash.tri 16,148 B envelope, verify 7.96 ms; 2^20 relation 71,081 B ([bake-off](../audit/succinct-profile-2026-10.md)).

## zk (envelope profile 2)

```rust
use zheng::execution::veil;

let (statement, proof) = veil::prove(&program, &public_input, &secret, budget)?;
veil::verify(&statement, &proof)?;
veil::verify_with(&statement, &proof, Some(&vk))?;
let envelope = zheng::envelope::prove_zk(&program, &public_input, &secret, budget, context)?;
```

`PrivateStatement`: program, public inputs, outputs, cycles, budget. `veil::prove_relation` / `verify_relation` serve callers that derive their own relation (joy's private state queries). `execution::zk::{prove, verify}` is the MPC-in-the-head fallback (scheme 1, linear size). measured: secret-preimage hash 63.9 KB, verify 10.0 ms, 4.1 ms with a cached key ([zk profile](../audit/zk-profile-2026-10.md)).

## verifying keys

```rust
use zheng::execution::VerifyingKey;

let vk = VerifyingKey::for_execution(&statement)?;   // or for_state
vk.program_key(); vk.digest();
```

derived by the verifier only — no constructor from parts, no deserialiser. `digest` = hemera tree root of the relation encoding; succinct and zk transcripts absorb it, so a proof is bound to its relation. a key whose program key differs from the statement's is rejected.

## envelope

```rust
use zheng::envelope::Envelope;

let bytes = envelope.to_bytes();
let envelope = Envelope::from_bytes(&bytes)?;   // canonical decoding only
envelope.verify(evidence.as_ref())?;            // runs the profile's verifier
```

`Envelope::{Public, Succinct, Zk, StatePublic}`; `EnvelopeError::{BadMagic, UnsupportedVersion, UnknownProfile, Truncated, TrailingBytes, NonCanonical, TooLarge}`. profile 4 (machine proof) lands with accumulation (`accumulation.md`, `machine.md`, phase 3 in this release); API: `machine::{prove, verify}`, `Envelope::Machine`; goal ≤ 64 KB, constant in steps; measured: the decider is 44–93 KB, but without recursion the whole proof grows with the steps — 83 KB (33 cycles), 146 KB (merkle-32), 384 KB (16,383 cycles, 3 segments), ~96 KB per 2^14-row segment (`audit/accumulation-2026-10.md`).

## retired and legacy

- public v2 (`prove_execution` / `verify_execution`, `DirectProof`) and state v1 (`prove_state_execution` / `StateStatement::verify_v1`) are read for one release.
- the folded trace API — `commit`, `open`, `verify_eval`, `verify`, `fold`, `decide`, `TraceProof`, `Accumulator`, the universal CCS, phi — compiles only with the cargo feature `legacy`, off by default. it is unsound (the fold is unchecked, the statement unbound, the constant wire free, the Brakedown code distance unproven; [[decider]] §soundness) and is removed in phase 5. its former size and cost figures were never measured on a sound construction and are withdrawn. `commit` refuses recursive axis/look openings (`CommitError::UnsupportedRecursiveOpening`).

see [[verifier]] for what each verifier checks, [[transcript]] for Fiat–Shamir, [[constraints]] for the CCS format.
