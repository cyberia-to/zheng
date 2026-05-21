# close soundness gaps (pattern-15)

## status: pending user approval

## the two gaps

### gap 1 — Fiat-Shamir transcript stubs (`verifier_steps.rs:88-90`)

```rust
for _ in 0..(num_vars * QUERIES_PER_ROUND) {
    steps.push(eq_step(Goldilocks::ZERO, Goldilocks::ZERO));
}
```

Each stub represents one `transcript.squeeze()` call in `Brakedown::open()` that
deterministically selects a query index. The stubs prove nothing — any prover can
supply any query indices. Sound verification requires constraining each squeeze via
Poseidon2 CCS.

### gap 2 — BBG root hash binding (`ccs/mod.rs:167`)

```rust
// TODO(pattern-15): H(lo.commitment || A_commit || N_commit) == lo.bbg_root
```

Currently `lo.bbg_root` is set to the raw commitment bytes. The trace already binds
`lo.bbg_root[i]` to trace registers via eq_step — but there is no proof that
`bbg_root = H(commitment || A || N)`. Gap 2 is **partially blocked** on BBG design
(A = accumulator commitment, not yet defined). See "blocked" section below.

---

## Brakedown transcript call sequence

```
transcript.new(seed)                      // absorb seed bytes
transcript.absorb(initial_commit.bytes)   // 32 B

for each r_i in point:                    // k rounds
    transcript.absorb(round_commit_i.bytes)  // 32 B
    for q in 0..20:                       // NUM_QUERIES squeezes per round
        challenge = transcript.squeeze()  // Poseidon2 finalize + re-seed
        idx = u64_le(challenge[0..8]) % codeword_len
```

`transcript.squeeze()` is:
1. `hasher.finalize()` — Poseidon2 permutation on current 16-element state + output
2. `Hasher::new()` + `absorb(hash.as_bytes())` — re-seed with 32-byte output (4 Goldilocks)

Each squeeze is one Poseidon2 permutation = 24 CCS instances via `partial_round_ccs`.
All 16 partial rounds and 8 trivial rounds are encoded, same as hash pattern-15.

The prover can replay the transcript from seed + round_commitments (already in Opening).
No changes to lens required.

---

## gap 1 implementation

### new struct: `TranscriptAux`

```rust
/// Prover-supplied intermediate Poseidon2 states for one Brakedown transcript squeeze.
pub struct SqueezeAux {
    /// Full 16-element Poseidon2 state at each of the 24 round transitions.
    pub round_states: [[Goldilocks; 16]; 25],  // state before each round (index 0..24) + after (24)
}

/// All squeeze aux data for one Brakedown opening (k rounds × 20 queries each).
pub struct TranscriptAux {
    pub squeezes: Vec<SqueezeAux>,  // k * 20 entries in order
}
```

### new function: `build_transcript_aux`

```rust
pub fn build_transcript_aux(seed: &[u8], opening: &Opening) -> TranscriptAux
```

Replays the Brakedown transcript from `seed` and `opening.round_commitments`.
For each of the `k × 20` squeezes, records the 16-element Poseidon2 state at
each of the 25 round boundaries (before round 0 through after round 23).
Returns the full `TranscriptAux`.

### new function: `transcript_steps`

```rust
pub fn transcript_steps(
    aux: &TranscriptAux,
) -> Vec<(CCSInstance, CCSWitness)>
```

Produces `k × 20 × 24` CCS pairs (16 `partial_round_ccs` + 8 `trivial_hash_ccs` per squeeze).
Uses the SAME Z_LEN_HASH=50 / num_rows=16 structure as pattern-15 hash steps.
Goes into the **hash accumulator** (not the axis/look accumulator).

### changes to `verifier_steps.rs`

Remove the stub loop (lines 88-90). Update docstring to say transcript steps are
produced separately by `transcript_steps()`. Update tests:
- `step_count_two_vars`: 4 + 1 = 5 (not 45)
- `step_count_four_vars`: 4 + 1 = 5 (not 85)
- `uniform_matrix_structure_for_folding`: still holds (all 5 are VZ_LEN=3)
- Keep all other tests unchanged

### changes to call sites in `ccs/mod.rs`

`build_axis_steps_from_trace` and `build_look_steps_from_trace` currently extend
the axis/look accumulator with `verifier_steps(...)`. Add a second return channel
(or separate function `build_axis_transcript_steps_from_trace`) that collects
the transcript CCS pairs and returns them for the hash accumulator.

Option A (clean): two separate functions per type:
```
build_axis_steps_from_trace()   → Vec<(inst_VZ3, wit_VZ3)>  (axis accumulator)
build_axis_transcript_steps()   → Vec<(inst_H50, wit_H50)>  (hash accumulator)
build_look_steps_from_trace()   → Vec<(inst_VZ3, wit_VZ3)>
build_look_transcript_steps()   → Vec<(inst_H50, wit_H50)>
```

Option B (bundled): return both from one function:
```
build_axis_steps_from_trace() → (Vec<VZ3_pair>, Vec<H50_pair>)
```

**Decision**: Option A. Keeps each function single-purpose and avoids tupled return types.

### new inputs required

`AxisOpening` gets a `seed: [u8; 32]` field — the transcript seed used in
`Brakedown::open()`. Same for `LookOpening`.

`build_axis_transcript_steps` takes `openings: &[AxisOpening]` (same slice as today)
plus the TranscriptAux (which it builds internally from seed + opening).

---

## gap 2 implementation (partial — blocked on A)

### what's known

- `commitment` = Brakedown commitment to BBG dimension polynomial (in LookOpening)
- `N` = namespace = `nox_op.namespace` (Goldilocks field element, already available)
- `A` = accumulator commitment — **not yet defined** by BBG design

### what's needed from BBG

BBG must define what `A_commit` is before Gap 2 can be fully closed. Candidates:
- The nox proof accumulator commitment (zheng Accumulator)
- The BBG state commitment from a previous epoch
- The account identifier hash

### what can be done now

Add `namespace: Goldilocks` and `A_commit: Option<[Goldilocks; 4]>` to `LookOpening`.
Set `bbg_root = H(commitment_bytes || A_bytes || namespace_bytes)` in
`look_openings_from_provider` when `A_commit` is `Some(...)`.
Add the Poseidon2 CCS steps for this hash when A is provided.

Constraint chain when A is Some:
1. eq_steps binding bbg_root to trace (already present)
2. `partial_round_ccs` × 24 constraining `Poseidon2(commitment || A || N) → bbg_root`

When A is None: keep the current `bbg_root = commitment_bytes` stub with explicit comment.

---

## file scope

| file | change |
|------|--------|
| `src/ccs/verifier_steps.rs` | remove stubs; update tests (step_count: 5 not 45/85) |
| `src/ccs/particle.rs` | add `SqueezeAux`, `TranscriptAux`, `build_transcript_aux`, `transcript_steps` |
| `src/ccs/mod.rs` | add `build_axis_transcript_steps`, `build_look_transcript_steps`; add `seed` to AxisOpening/LookOpening; add Gap 2 hash steps when A is Some |
| `src/lib.rs` | update re-exports for new types |

No changes to lens, hemera, or nox.

---

## test plan

### gap 1

- `transcript_steps_count`: for k=2, 20 queries → 2×20×24 = 960 CCS pairs
- `all_transcript_steps_satisfied`: all 960 pairs satisfy their CCS instances for a real opening
- `transcript_steps_reject_wrong_index`: if query_responses index is wrong, at least one step fails

### gap 2

- `look_hash_binding_satisfied`: when A is provided, all Poseidon2 steps satisfy
- `look_hash_binding_fails_wrong_root`: wrong bbg_root → at least one step fails

---

## blocked

Gap 2 (A): wait for BBG to define `A_commit`. Until then, add `namespace` field
(N is known), set `A_commit: Option<[Goldilocks; 4]> = None`, and implement the
full hash binding but guard it on `A_commit.is_some()`. Comment documents the interface.

Gap 1 codeword value authentication: the current lens Brakedown verifier ignores
`_qval` — codeword values are not authenticated against the commitment. Closing this
gap requires Merkle paths in the Opening::Tensor struct (a lens change). Tracked
separately; out of scope here.

---

## session estimate

- Gap 1 implementation: 2 sessions (TranscriptAux build, transcript_steps, tests)
- Gap 2 partial (N only, A=None): 0.5 session
- Gap 2 full (after BBG defines A): 0.5 session
