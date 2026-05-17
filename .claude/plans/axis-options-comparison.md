# axis linkage options: comparison

## the problem

`verifier_steps()` produces a separate fold sequence (VZ_LEN=3).
The main trace fold uses Z_LEN=33. They cannot share an accumulator.
The axis_acc proves a Brakedown opening is valid.
The main trace's axis row has r4=commitment, r6=eval_point, r7=value.

Three things must be verified together to be sound:
1. r4 (commitment) == commitment used in axis_acc  
2. r6 (eval point) == point used in axis_acc
3. r7 (value) == value proved by axis_acc

Brakedown soundness guarantees: if (1) and (2) hold, then (3) follows
automatically — the opening uniquely determines the value. So binding
(1) and (2) is sufficient. (3) can be left to Brakedown.

---

## option A — statement binding, no nox change

Add to `Statement`:
```
axis_openings: Vec<(commitment: [u8; 32], eval_point: u64)>
```

`build_ccs_from_trace()` keeps `pattern_axis() = trivial_ccs()`.

The verifier (outside the circuit) checks:
- For each axis row i: `axis_acc.binding_commitment_i == statement.axis_openings[i].commitment`
- `axis_acc.eval_point_i == statement.axis_openings[i].eval_point`

The prover constructs the proof with matching Statement; the verifier rejects mismatches.

| property | value |
|----------|-------|
| soundness: commitment bound | ✅ verifier-side (not circuit) |
| soundness: eval point bound | ✅ verifier-side |
| soundness: value (r7) | ✅ follows from Brakedown |
| nox change | ❌ none |
| circuit constraints per axis row | 0 |
| Statement growth per axis call | +40 bytes (32 commitment + 8 point) |
| prover: main acc overhead | 0 extra field ops |
| prover: axis acc overhead | ~45 CCS steps × (VZ_LEN=3) per call |
| verifier: extra checks | O(N_axis) byte comparisons |
| proof size increase | +1 axis_acc decide proof |
| implementation effort | medium — Statement + verifier logic |
| security | ✅ sound (statement is public input, cannot be forged) |

Weakness: Statement grows with trace. If a program calls axis 1000 times,
Statement carries 40 KB of commitment data. This is fine for verification
but bloats the public input.

Also: row ordering. The verifier must know which rows in the main trace are
axis rows and in what order, to match them to `axis_openings`. This requires
either encoding step positions in Statement or scanning the trace (prover-side).

---

## option B — circuit constraint, nox update

nox emits commitment bytes in reserved registers for pattern 0:
```
r10 = commitment_bytes[0..8]  — first  8 bytes as Goldilocks element
r11 = commitment_bytes[8..16] — second 8 bytes
r12 = commitment_bytes[16..24]— third  8 bytes
r13 = commitment_bytes[24..32]— fourth 8 bytes
```
(r8=budget_in, r9=budget_out are fixed — r10-r13 are free)

`pattern_axis()` gets 5 constraints:
- 4 linear: `r10_t = C_limb_0`, ..., `r13_t = C_limb_3`  (commitment binding)
- 1 linear: `r9_t - r8_t + 1 = 0`                          (budget)

The constants C_limb_0..3 are baked into the constraint matrices at CCS build time.
At fold time each axis row contributes its own instance with its specific commitment.

The axis_acc's binding steps check the same 4 limbs. The circuit and the opening
are consistent by construction — both encode the same commitment bytes.

| property | value |
|----------|-------|
| soundness: commitment bound | ✅ circuit constraint (32 bytes = 256-bit binding) |
| soundness: eval point bound | ⚠️ r6 is in circuit but not constrained against axis_acc |
| soundness: value (r7) | ✅ follows from Brakedown + commitment binding |
| nox change | ✅ yes — emit r10-r13 for pattern 0 |
| circuit constraints per axis row | 5 (4 commitment + 1 budget) |
| Statement growth per axis call | 0 bytes (commitment is in the trace) |
| prover: main acc overhead | +5 constraints per axis row |
| prover: axis acc overhead | same ~45 CCS steps per call |
| verifier: extra checks | 0 (circuit handles it) |
| proof size increase | +1 axis_acc decide proof |
| implementation effort | medium — nox change + updated pattern_axis() |
| security | ✅ sound (full 256-bit commitment binding in circuit) |

Note on eval point: r6 (eval point) is in the main trace but not circuit-linked
to axis_acc. To fully close: add `r6 = eval_point` to axis_acc steps (currently
not in verifier_steps — would need an additional eq_step at the front). This is
optional: Brakedown query structure implicitly binds the eval point.

---

## head-to-head

| dimension | A (statement binding) | B (circuit constraint) |
|-----------|----------------------|------------------------|
| nox change | no | yes |
| soundness | same | same |
| security model | public input | circuit |
| commitment binding strength | 256-bit via statement | 256-bit in circuit |
| eval point binding | explicit in statement | implicit (Brakedown) |
| proof size | identical | identical |
| prover: main trace overhead | 0 | +5 ops per axis row |
| prover: axis acc | same | same |
| verifier overhead | +O(N_axis) byte checks | 0 extra |
| statement size | +40 bytes per axis call | 0 |
| implementation effort | 2-3 days | 1-2 days (nox coord) + 0.5 day |
| when can we start | now | after nox emits r10-r13 |

---

## speed impact

The axis_acc fold is the dominant cost in both options — ~45 CCS steps with
VZ_LEN=3 per axis instruction. This is identical for both options.

The difference (5 extra constraints in main trace for option B) is noise:
the main trace prover iterates over all rows regardless; 5 extra constraints
per axis row add O(N_axis × 5) field multiplications total — unmeasurable
against the O(N_total × Z_LEN) sumcheck cost.

Verifier side: option A adds a loop over N_axis byte comparisons (O(N_axis × 32)
byte ops — nanoseconds). Option B avoids this entirely but requires nox changes.

**Speed verdict: identical at any realistic N_axis. Speed is not the deciding factor.**

---

## recommendation

Option A if: you want to proceed now with no nox coordination.  
Option B if: nox can emit r10-r13 in the same sprint — cleaner long-term.

Neither is complete without also binding the eval point (r6). The current
`verifier_steps()` takes `point: &[Goldilocks]` — adding an `eq_step(r6, point[0])`
at the front of verifier_steps() would close that gap for option B.
