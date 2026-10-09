---
tags: zheng, audit, recursion, ivc, review
crystal-type: audit
crystal-domain: crypto
---
# recursion — adversarial soundness review of PR #53, 2026-10-09

Target: zheng `feat/ivc` 5650094 (PR #53, stacked on `feat/accumulation`,
PR #51): `rs/src/recursion/`, `rs/src/fs.rs`, `rs/tests/recursion.rs`,
`specs/recursion.md`, `specs/soundness.md` § recursion,
`audit/recursion-2026-10.md`. Stand: the siblings of stand B (lens and joy
`feat/accumulation` 3cf2aaa / 69a15ef, hemera cf28a64, nox 2f09ca3).
Fixes and attack tests: branch `fix/ivc-review`. Machine: Apple M4 Max,
`--release`, shared with other agents.

## findings

| id | severity | finding | status |
|---|---|---|---|
| F1 | soundness (verifier) | the final verifier hashed the proof's state with a native interpreter and ignored its failure; an extension value in a base slot made the "digest" raw, prover-chosen lanes, unbinding the state from the last step's public input | fixed |
| F2 | malleability | grinding nonces were absorbed as `Goldilocks::new(n)` without a range check: `n` and `n + p` verify alike | fixed |
| F3 | ledger gap | the τ, shift-reduction and boundary-batching rounds had no ledger row | rows added (all ≥ 188 bits) |

### F1 — the final state was not bound to the last public input

`ivc::verify_prepared` computed `x = state::digest_native(proof.state)` and
verified the last step's proof against `x`. `digest_native` ran the generic
digest on a fresh `Native` interpreter and returned its output without
looking at `Native::error`. `Native::permute` records "a base lane holds an
extension value" and from then on skips every permutation (the outcome is
"fixed" — but nobody read it), so the four digest limbs were the raw rate
lanes 0..4 of the state sponge's last block: `pv.point[20]` (three lanes)
and `pv.point[21].c0` — coordinates of the carried circuit-key claim.

The native step verifier reads the state's spot points `ω^s` only through
`eq_pow`, so an extension value there trips nothing else. The forger:

1. runs a **base** step (live = 0, verifying nothing) for the last segment;
   its circuit outputs the initial state, digest `d`;
2. writes a state by hand — step count `S − 1`, any chain prefix, any
   boundary rows, the zero accumulator with `spot[0].x = 1 + T`, deferred
   claims at points of its choice with their true values — and sets
   `pv.point[20..22]` so the raw lanes equal `d` (`pv.value` is recomputed
   as `P̄_V(pv.point)`, which the key's public evaluation allows);
3. proves the last segment with the honest prover from that state and `d`.

Every final check passes: context, chain, step count, cyclic boundary, the
three folded deferred claims, the decider. Test
`recursion::review::a_state_unbound_from_the_last_public_input_is_refused`
does this on `tree-12` (two segments) with segment 0's pre-committed word a
replaced by a zero table: **accepted on 5650094** (run against the
unpatched tree: `a state unbound from the step's public input was
accepted`), refused after the fix. Consequence: the prover proves only the
last segment, from a machine row (`b_last`), memory running sum and
deferred claims it chose — a false output follows from any segment that
satisfies the constraints from a chosen start.

Reach: the wire form (`IvcProof::from_bytes`) encodes a base item as one
canonical limb, so a byte proof could not carry the extension value; the
struct API `ivc::verify(&MachineStatement, &IvcProof, _)` accepted it.

Fix: `state::is_canonical` (every base item has zero extension
coefficients) is part of the final verifier's shape check; `digest_native`
returns `Err` when the native interpreter recorded a failure (it is also
used by the decider transcript). With base items base, the native digest
equals the circuit's (`absorb_free` takes the base limb).

### F2 — grinding nonces

`AccProof::{comb_nonce, query_nonce}` are `u64`, absorbed as
`Goldilocks::new(n)` (no reduction) and hashed through `as_u64` (reduced),
and the wire reader takes them as raw `u64`: `n + p` is a second encoding
of a proof. `step::check_shape` now requires both `< p`
(`recursion::review::a_non_canonical_grinding_nonce_is_refused`).

## items checked sound

1. **native = circuit.** One program over `Ops`; the circuit's checks that
   the builder only records at witness time are each forced by the AIR:
   base lanes by memory (a slot fingerprints the base column, the cell
   must be base), `bits` of an extension by memory on `BVAL`, Merkle
   direction booleanity (`node·bit·(bit − 1)`), roots (`live·ROOTCHK`).
   Hemera gadget: rows 0–3 compute `MDS`, full rounds 0–3, the 16 partial
   rounds through `w = u⁻¹` pinned uniquely by `uwu = u`, `wuw = w`
   (`w = 0` iff `u = 0`), full rounds 20–23 — checked against hemera by
   `the_row_layout_computes_hemera`. Decompositions: 64 boolean digits,
   16-bit chunk accumulation, `hi = 2^32 − 1 ⇒ lo = 0`
   (`the_decomposition_refuses_non_canonical_and_non_boolean_digits`:
   `v + p` passes every accumulation row and is refused by canonicity
   only; a digit 3 compensated by its neighbour is refused by
   booleanity). Memory: write-once cells with preprocessed addresses and
   multiplicities (`−reads` at the writer), cyclic running sum through the
   boundary row. `every_cell_the_circuit_reads_is_constrained` tampers
   every phase-1 and phase-2 cell of an honest run (gates, wide/free/keep
   lanes, a decomposition, a Merkle opening with root check): every cell
   breaks a constraint or the memory except the ones free by design
   (unused operands, unread free outputs, decomposition scratch outside
   its phase, root/direction cells with no check, padding).
2. **`live`.** `n[LIVE] = LIVE` on every row including the wrap (the
   circuit's successor of the last row is its own row 0 via `b_v`),
   boolean, written to memory at row 0 slot 16, so the select gate and the
   assertion gating read one value. `live = 0` makes the step output the
   initial state of the context it was given (step count 0, chain 0):
   `the_base_step_outputs_the_initial_state_whatever_it_is_given`. A base
   step after the first restarts the count; reaching `step = S`,
   `chain = D` again needs `S` verified steps. The second half of the F1
   test proves a base step in last position under its honest state: refused.
3. **binding.** `x = H(state)` is the step's first absorb and the circuit's
   output row (`OUT·(o8 − pin)`, deferred in `G`); the state carries the
   context (statement digest: program, input, output, cycles, geometry;
   the chain `D`; `g0, pn0, pv0`), checked once at the end; `P̄_nox` is
   evaluated at `bits(step)`, the chain absorbs word a's root in step
   order and must equal the header's `D`, from which `(α, β)` and the
   context derive — no splicing of programs or reordering of segments.
   The circuit key is bound by the `P̄_V` claim against the parameters'
   key. (F1 broke this link for the final state only.)
4. **deferred claims.** Each step folds the carried claim and the new one
   along their line: `h(0)` = carried value (bound by `x`), `h(1)` = new
   value (from absorbed messages), `h(2..=deg)` absorbed before `r`.
   One claim of each kind lives in the state; it cannot be dropped or
   zeroed without changing `x`; the final verifier evaluates all three
   exactly (`Relation::g`, `pbar_nox`, `pbar_v`). Degrees 32 / 52 / 22
   match `G` (8 + 3·8) and the multilinear claims (`n + 32 + 5`, `n + 7`);
   an honest fold would fail otherwise.
5. **base case.** The initial state is a function of the context only:
   zero accumulator (claims true for the zero word at any point), claims
   at the zero point with values `g0, pn0, pv0` hashed into the context.
   The first verified step takes `b_in` free and records it as `b_first`;
   the cyclic check `b_first = b_out(last)` closes the run.
6. **Fiat–Shamir.** Step order: `x`; root a, OOD answers (points from the
   root alone); root b, `ζ_b`, answers; `(α_V, β_V)`; root c, answers;
   boundary rows; `τ`, seeds; zerocheck rounds; column and public values;
   `γ_n, γ_v`; line folds; shift batching, rounds, values; boundary
   batching; accumulation (γ, rounds, evaluations, comb grinding, `r`,
   new root, OOD, query grinding, indices). Every value a challenge
   depends on is absorbed before it, in the circuit and natively (one
   program). Indices exclude the limb `p − 1`.
7. **ledger.** Recomputed below from `lens::rspcs::soundness` formulas
   (Johnson `m = 19` at rate 1/16, `m = 7` at 1/64; `|K| = p³`, 192.00
   bits). The "IVC composition" row is stated as conjectured with the
   right reason (recursive Fiat–Shamir with hemera evaluated in the
   relation); its argument "a final state is accepted only if it is a
   successor of the initial state through `S` verified steps" was false
   for the struct API until F1's fix.
8. **`fs.rs` refactor.** The trait forwards to lens's own `absorb_fp3`,
   `squeeze_fp3`, `absorb_fp3_slice`; the generic provers changed only
   their signatures. `tests/transcript_pin.rs` hashes the machine proof
   bytes of `add` and of `tree-7` in 2^8-row segments: identical on #51
   (`feat/accumulation` 75f3846) and #53 (`196debd3…`, `ce2fd453…`), now
   pinned.

## ledger, recomputed (`recursion::params::tests`)

| row | rate 1/16 | rate 1/64 | recomputed |
|---|---|---|---|
| accumulation batch | 177.77 | 177.67 | `192 − log₂ L − log₂(J − 1)`, `L = 19·16` / `7·64`, `J = 64` / `47` |
| accumulation sumcheck | 182.75 | 182.19 | `192 − log₂ L − 1` |
| accumulation combine (22 / 20 grinding bits) | 128.00 | 128.65 | `−log₂(3·(ε_mca + L/|K|)) + pow` = 128.002 / 128.652 |
| accumulation OOD | 155.50 | 154.39 | `−(2 log₂ L − 1 + s(ℓ − 192))`, `ℓ = 21` |
| accumulation spot (24 grinding bits) | 128.01 | 128.42 | `−t·log₂(1 − δ) + 24`, `t = 53` / `36`, `1 − δ = (1 + 1/2m)·√ρ` = 128.014 / 128.417 |
| decider WHIR | 128.01 | 128.24 | lens `security_bits` |
| zerocheck μ (structured powers, `B = 9`) | 187.42 | 187.42 | `192 − log₂ 24` |
| zerocheck τ | 188.09 | 188.09 | `192 − log₂ 15` (added) |
| zerocheck round (degree 9) | 188.68 | 188.68 | `192 − log₂ 10` |
| shift round (degree 2); ζ, β | 191.00 | 191.00 | `192 − 1` (added) |
| shift / boundary column batching | 189.42 | 189.42 | `192 − log₂ 6` (added) |
| line folds G / P̄_nox / P̄_V | 187.00 / 186.30 / 187.54 | same | `192 − log₂ {32, 52, 22}` |
| column batching γ_n, γ_v | 189.19 | 189.19 | `192 − log₂ 7` |
| circuit memory α | 172.91 | 172.91 | `192 − log₂(17·2^15)` |
| circuit memory β (pairs) | 154.83 | 154.83 | `192 − 2 log₂(17·2^15) + 1` |

Tightest: combine 128.002 and spot 128.014 at rate 1/16 — at the floor by
construction (`comb_pow`, `query_pow` are the least grinding reaching 128).

## tests added (`fix/ivc-review`)

- `recursion::review::a_state_unbound_from_the_last_public_input_is_refused` (F1; ~130 s)
- `recursion::review::the_base_step_outputs_the_initial_state_whatever_it_is_given`
- `recursion::review::a_non_canonical_grinding_nonce_is_refused` (F2)
- `recursion::circuit::tests::every_cell_the_circuit_reads_is_constrained`
- `recursion::circuit::tests::the_decomposition_refuses_non_canonical_and_non_boolean_digits`
- `tests/transcript_pin.rs::machine_proofs_are_byte_identical_to_the_pre_recursion_prover`
- ledger rows τ, shift, boundary batching in `recursion::params::tests`

## residual (not defects)

- `Native` stops hashing after its first failed check; every remaining
  caller that does not inspect the error (`ctx_native`,
  `statement_digest`, `run_challenges`, `pre_points` in the prover,
  `leaf_digest` in the wire decoder) hashes base-typed inputs only.
- The single-cell scan shows no unconstrained cell; it does not prove the
  absence of multi-cell under-constraint — the "recursion circuit = the
  step verifier" row stays *tested, not proven*.
