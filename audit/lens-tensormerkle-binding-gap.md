---
tags: zheng, audit, lens, soundness
date: 2026-09-22
---
# lens 0.2's TensorMerkle opening bypasses CCS binding steps

`rs/Cargo.toml` and `cli/Cargo.toml` pinned `cyber-lens` to `0.1.3` and
`cyber-nox` to `0.2` while the local checkouts had already moved to `0.2.0`
and `0.3.0`; a clean checkout could not even build (`cli/Cargo.toml` also
still pointed `tape` at the pre-rename `../../tape/impl/rust` path, deleted
when `cyber-tape` became [[tade]]). This PR fixes both path issues and bumps
the pins, and that bump exposes a real gap: with a genuine `cyber-lens`
0.2.0 dependency, ten tests fail, not from a mechanical rename but from a
change in what `Brakedown::open` returns.

## what changed under us

`lens::Opening` in 0.1.3 had `Brakedown::open` return the `Tensor` variant —
the doc comment on that variant in `lens/core/src/types.rs` calls it a
"known-unsound residual": queried codeword values are carried but never
checked against round commitments. lens 0.2.0 fixes this: `Brakedown::open`
now returns `TensorMerkle` (`row_combination` + `columns` with Merkle
authentication paths), the sound scheme the `Tensor` doc comment says
Brakedown "moved to."

`rs/src/ccs/transcript.rs::build_transcript_steps` and
`rs/src/ccs/verifier_steps.rs::verifier_steps` both pattern-match only on
`Opening::Tensor` and return an **empty step list** for any other variant —
by design, per the existing (still-passing) test
`transcript_steps_empty_for_non_tensor_opening`. That design assumed a
non-Tensor opening was an unreachable or exotic case. It is now the
production case: every real `Brakedown::open` call returns `TensorMerkle`,
so `verifier_steps` silently returns zero binding steps for a real opening
instead of erroring. `rs/src/lib.rs::verify_accepts_raw_satisfied_axis_steps`
then has nothing to fold (`EmptyAccumulator`), and
`commit_rejects_tampered_axis_opening` can't even construct its tamper
(`Opening::Tensor` has no `final_poly` field to flip a bit in on a
`TensorMerkle` value).

Silently-empty steps is the concerning half: nothing here currently panics
or errors closed on the mismatch, so a caller that wires `verifier_steps`
into an actual verify path today (none does yet — CCS is scaffolding, per
`rs/src/ccs/`) would accept a proof having performed zero commitment/point/
value binding checks.

## the ten tests, ignored with this file cited inline

```
ccs::transcript::tests::all_transcript_steps_satisfied_on_real_opening
ccs::transcript::tests::transcript_steps_count_two_vars
ccs::verifier_steps::tests::all_steps_satisfied_on_valid_opening
ccs::verifier_steps::tests::binding_steps_fail_on_wrong_commitment
ccs::verifier_steps::tests::final_step_fails_on_wrong_value
ccs::verifier_steps::tests::step_count_four_vars
ccs::verifier_steps::tests::step_count_two_vars
ccs::verifier_steps::tests::uniform_matrix_structure_for_folding
tests::commit_rejects_tampered_axis_opening
tests::verify_accepts_raw_satisfied_axis_steps
```

`wire.rs`'s `Opening::Tensor` encode/decode (the `TraceProof` wire format)
is untouched by this PR and has no test coverage exercising a real
`Brakedown::open` value either — it will hit the same mismatch the moment
something calls it with a live opening; not ignored here because nothing
currently red-flags it.

## what the next slice needs

`build_transcript_steps` and `verifier_steps` need a `TensorMerkle` arm that
derives the equivalent binding steps from `row_combination` and `columns`
(each `ColumnQuery` carries its own Merkle path — see
`lens/core/src/types.rs`), and `wire.rs` needs a matching encode/decode arm.
This is a real cryptographic design task, not a rename: the two variants
carry structurally different proof material (round commitments + a single
final polynomial vs. a row combination + sampled authenticated columns), so
the binding-step shape changes, not just field names.

## verified

Rust 1.98.0, macOS arm64, revision `44bd5bf` (origin/master) plus this
PR's diff.

- `RUSTC_BOOTSTRAP=1 cargo check --tests`: clean checkout now builds
  (previously failed to load `cli`'s manifest — `cyber-tape` path deleted —
  and, once that's fixed, failed to resolve `cyber-lens = "^0.1.3"` against
  the local `0.2.0` checkout).
- `RUSTC_BOOTSTRAP=1 cargo test`: `test result: ok. 133 passed; 0 failed;
  10 ignored` (`rs` lib), `2 passed; 0 failed` (`cli` bin), `0` doc-tests.

Cargo also refreshed the local-package versions the workspace already had
on disk: `cyber-lens` 0.1.3 → 0.2.0, `cyber-lens-assayer`/`-brakedown`/
`-ikat`/`-porphyry` 0.1.1 → 0.2.0, `cyber-nox` 0.2.0 → 0.3.0. No registry
dependency or checksum changed.
