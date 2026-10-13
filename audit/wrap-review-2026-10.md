---
tags: zheng, audit, recursion, wrap, review
crystal-type: audit
crystal-domain: crypto
---
# wrap steps — adversarial review, 2026-10-10

Review of zheng #56 (`feat/wrap` 5f39786, stacked on #53 `feat/ivc`, #52
merged in) and lens #21 (`feat/field-native-whir` c91f55a). Contract:
`specs/recursion.md` § final verifier, § field-native WHIR, § wrap;
ledger: `specs/soundness.md` § field-native WHIR and wrap; build report:
`audit/wrap-2026-10.md`. Branch `fix/wrap-review` (off `feat/wrap`).
Apple M4 Max, 48 GB, `--release`.

## verdict

No soundness hole found. Two hardening fixes (H1, H2), two spec
corrections (D1, D2), one informational note (I1). Every new test passes
on the fixed branch; the PR's own tests are unchanged and pass.

## method

The previous review (#53) found a native-vs-circuit divergence (a
non-base value stopping the native sponge, so the state the native
verifier read was not the one the last public input hashed). This review
looked for that class everywhere the wrap adds an interpreter path, and
at every new protocol step:

- every `Ops` method natively (`Native`, plain and batched) and in the
  circuit (`Builder` + the circuit AIR) on adversarial values: Fp3 values
  in base lanes, non-bit Merkle directions (binary and 4-ary), bits of an
  Fp3 value, an Fp3 Merkle root, a zero inverse, the `p − 1` index limb,
  nonces `≥ p`;
- every `o.value(…)` in verifier code (data the circuit would bake as a
  constant): `ops::inv`, `step::is_zero` (sound gadgets), and the final
  mode's key evaluation and wiring weight (native only — H2);
- the circuit's cells under the final mode (no memory argument): which
  cells the linear wiring pins, against the memory argument;
- transcript order of every wrap message against the challenges it feeds;
- the decider, the deferred claims, the public digest `X` and the header.

## findings

### H1 — a wrap key was not bound to the recursive proof it verifies (fixed)

`wrap::verify_statement(st, ivc_whir, k, fp)` prepared the statement under
`key(ivc_whir, fp.log_rows)` and verified the final wrap under `k`, whose
inner circuit runs the IVC final verifier for the step size and WHIR
parameters `k` was derived from. Nothing compared the two. A header with
another step size was refused only incidentally: the deferred nox-public
claim, split at the header's `n + 32` instead of the key's, did not
evaluate to the carried value (`pbar_nox`), and for a key more than five
step bits below the header `point.split_at(n + 32)` would panic — not
reachable today, the step circuit needs `n ≥ 15` and `prepare` caps
`n ≤ 20`. Not exploitable (the statement digest, `X` and the claim's
evaluation all differ), but the binding rested on an accident.

Fix: `WrapKey::ivc = (WhirParams, n)`, set by `derive_key_ivc`, carried by
`derive_key_wrap`; `verify_final` refuses `(prep.key.params.whir,
prep.key.params.n) ≠ k.ivc` before evaluating anything. Tests:
`recursion::wrap::review::a_final_proof_under_another_step_size_is_refused_by_its_key`,
`tests/wrap_review.rs` (header `log_rows + 1`).

### H2 — a final-mode key could be put inside a circuit (fixed)

The final verifier evaluates the key's columns at `ρ` and the wiring
weight's closing term in the field (`o.value`), as native verifiers may.
`derive_key_wrap` accepted a final-mode inner key: inside a circuit those
values become constant gates of the key derivation's dummy proof, so the
level would check the inner zerocheck against a key that is not the
circuit's. Completeness failed (the prover's layout check refuses), so no
deployed chain was affected; soundness of such a key would be void.

Fix: `derive_key_wrap` refuses a final-mode inner key. Tests: both review
tests above assert the refusal.

### D1 — "the binary node's tag and the leaf sponge's capacity tag keep the three input kinds apart" (corrected)

A 4-ary node's input is its four children, sixteen lanes, no tag, and the
siblings are the prover's: with siblings `(NODE_TAG, 0, 0, 0)` and
`(0, 0, 0, 0)` a 4-ary input equals a binary node's input; a leaf block's
likewise. The trees stay binding because the verifier's level schedule
(depth and fan-in per level, from the shape) never parses one position
two ways, and the truncated permutation is collision resistant (2^128
generic). `specs/soundness.md` § field-native words now says so.

### D2 — grinding priced in; the ledger test pins another profile (corrected)

Every wrap row is ≥ 128 with grinding priced as hemera work. Removing
grinding, the weakest rounds are 104.42 (inner 1/64), 104.29 (inner
1/256, 24 bits) and **98.02** (final 1/256: `shift_2` after 30 bits of
query grinding). The spec now states the interactive values and that the
`Q·2^-128` bound counts grinding permutations in `Q`. The PR's
`every_ledger_row_of_the_wrap_profiles_reaches_128_bits` checks the inner
1/256 level with 30 grinding bits while the measured chain
(`ZHENG_WRAP=6i,8i,8f:30`) ran it with 24; the new test checks the shipped
chain.

### I1 — base symbols' extension limbs (informational)

A round-0 opening of a base word is hashed and folded from `c0` only; an
in-memory `WrapProof` whose base symbols carry non-zero `c1`, `c2` verifies
as the same proof. The wire form carries one limb per base symbol, so the
bytes are identical and canonical (`tests/wrap_review.rs` asserts it).

## checked sound

| item | argument | test |
|---|---|---|
| `Ops` native vs circuit on refused values | each value refused natively, when computed (the prover cannot re-choose it), breaks the circuit's rows in both modes: a local constraint, or the memory argument (inner) and the wiring (final) | `values_the_native_verifier_refuses_break_both_wrap_modes` |
| `G` compiled (8,212 gates) vs `Graph::eval` | the compiler rewrites one polynomial (affine forms, fused products; the only inverse is of a nonzero constant coefficient) | PR's `expr` tests |
| final mode, linear wiring | `slot_values` is linear (no constant, checked per row); every recorded read is wired (`reads` = Σ builder reads); `λ` after `W1`'s root and OOD; `u_λ` and the key from the verifier's own key; every phase-1 cell pinned by a local constraint or a nonzero `u_λ` coefficient, and none the memory argument pins is left to the wiring's choice | `the_linear_wiring_pins_every_cell_the_memory_argument_pins` |
| successor columns sent | `next_cols` from `Graph::used_inputs` of the final graph (structural, an over-approximation); unsent successors enter as the verifier's zero, never the prover's; the sent ones bound by the `nxt` row-column weight | `tests/wrap_review.rs` (each of 20 tampered) |
| claims as WHIR weights | OOD, row × column (eq and cyclic `nxt`), wiring: every value absorbed and every weight's challenge squeezed before WHIR's `γ`; weights multilinear (WHIR Thm 5.2, `d* = 3`) | `tests/wrap_review.rs` |
| 4-ary levels, shared trees | directions from transcript limbs `≠ p − 1`; fixed level schedule; a group's leaf hashes its members in order, split by width; the verifier supplies one root per group | PR's `circuit`, `whir` tests; D1 |
| decider in circuit | instance (accumulator root, claims, key claim) absorbed under tag `DECIDE`; key root a constant; `(1 − g_6)K̃_lo + g_6K̃_hi` checked on the line | PR's tests |
| deferred nox-public claim | carried in `FinalProof`, evaluated natively from the statement (`pbar_nox`) before the wrap; its point and value enter `X`, so a true claim at another point is refused by the wrap | `tests/wrap_review.rs` |
| level binding | each level outputs `X = H_PUBLIC(publics, claim)`; the IVC level asserts context, chain, step count, cyclic boundary against them and uses the challenges and constants in `G`; a wrap level recomputes `X` for the level below | `tests/wrap_review.rs` (inner and final proofs under any other `X`, under the other level's key) |
| inner-mode memory | cyclic successor: the running sum telescopes (`Σ δ = 0`); every slot row has `MEM`; multiplicities preprocessed | PR's `circuit` tests |
| grinding nonces | `< p` in shape, absorbed as one limb; unused nonces zero | PR's `whir` tests |

`tests/wrap_review.rs` also tampers every AIR and opening message of a
final proof alone (local, successor, zerocheck, OOD, WHIR OOD, folding
sumchecks, final polynomial; `+1` and `+T`): **546 tampers, 546
refused, 0 panics**.

## ledger, recomputed

`shift_2` of the final level (rate 1/256, `ℓ = 20`, folding 4): round 1
has rate 1/2^11, Johnson `m = 13`, 18 queries, 30 query-grinding bits;
round 2 rate 1/2^14, Johnson `m = 3`, one OOD sample.
`log(1 − δ_1) = −11/2 + log2(1 + 1/26) = −5.4456`; queries
`18 × −5.4456 = −98.02`; the list term `log2 3 + 14 + log2 19 − 192 =
−172.2` is negligible; `98.02 + 30 = 128.02`. Fresh-word binding
`−(2·(log2 9 + 8) − 1 + (20 − 192)) = 150.66`. Wiring `192 − 18 =
174.0`. All agree with `wrap::ledger`.

| level | weakest (grinding priced) | interactive weakest |
|---|---|---|
| inner 1/64, 24 bits, `n = 16` | fold_0 128.24 | 104.42 |
| inner 1/256, 24 bits, `n = 15` | shift_1 128.29 | 104.29 |
| final 1/256, 30 bits, `n = 14` | shift_2 128.02 | 98.02 |

## tests and cost

| test | time | peak RSS |
|---|---|---|
| `recursion::wrap::review` (4 tests) | 12 s | 4.9 GB |
| `tests/wrap_review.rs` (one chain: IVC 1/16 → inner 1/16 → final 1/16) | 149 s | 11.4 GB |
| PR's `tests/wrap.rs` (same chain, unchanged) | 102 s | 12.7 GB |
| `cargo test --lib` | 274 passed, 3 ignored | — |

## not covered

- the shipped 1/256 levels end to end (32–38 GB, 13–20 min a chain); the
  review chain runs every level at 1/16, the same code paths;
- the wrap composition and recursive Fiat–Shamir stay conjectured;
- lens #21 adds only soundness terms and a spec section; checked against
  the formulas above, no change needed.
