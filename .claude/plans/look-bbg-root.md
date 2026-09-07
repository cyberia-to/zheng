# look ↔ BBG_root: putting the state root in the Statement

Status: IMPLEMENTED 2026-09-07 (branch feat/look-root). All four zheng-side
items landed: Statement.bbg_root (+ absorb after focus_bound — transcript
format break logged in CHANGELOG; accumulator-size stabilisation was out of
scope, so one more break may follow), root_to_bytes packing helper,
per-look-row eq steps binding root_from_leaves(leaves) to the public root
limbs inside build_look_steps_from_trace, and the LookBinding commit gate
(zero root = no-state-read sentinel, look rows against it reject). Note's
caveat about commit() not taking a Statement was stale — it does, so the
gate lives there. e2e + negative + inheritance tests in rs/src/lib.rs; the
bbg-side look_e2e.rs consuming the field is bbg's (M6) follow-up.

## the gap

`build_look_steps_from_trace` (ccs/mod.rs) already binds each look opening all
the way up to the root: opening soundness → value = r[7] → point = corner of
r[6] → commitment = `leaves.dims[r[5]]` → `root_from_leaves(leaves)` = trace
registers r[4], r[11], r[12], r[13]. But the root registers come from the
*program's object* — witness data. Nothing binds them to a public value, so a
prover can fabricate a self-consistent state (any leaves, any root), put its
root in the object, and every binding holds. The residual in
axis-verifier-integration.md ("look (17): BBG_root in Statement") is exactly
this missing final link: the root must be a **public input**.

## what bbg now provides (all landed, nothing else needed from bbg)

- `BbgState::root() -> Particle` — the BBG_root as `[u8; 32]`: four
  Goldilocks limbs, little-endian, packed limb i at bytes `[8i, 8i+8)`.
  This is the exact packing of `zheng::root_from_leaves` output
  (see `bbg/rs/src/state.rs::compute_root`).
- `BbgState::root_leaves() -> zheng::RootLeaves` — the 14-leaf preimage,
  structurally identical to what the in-circuit replay recomputes.
- serde (new, M6): `bbg::QueryProof`, `lens::Commitment`, `lens::Opening`
  Serialize/Deserialize behind a `serde` cargo feature in both crates, wire
  format pinned by golden fixtures. Docs:
  `bbg/docs/api/query-proof-wire.md`. A statement's root field needs no
  special serde — it is a plain `[u8; 32]` like `program_hash`.

## what zheng must add

1. **`Statement.bbg_root: [u8; 32]`** (types.rs). Use the `compute_root`
   packing above; `[0u8; 32]` for programs with no look rows (no real state
   has the zero root — it is the "no state read" sentinel). An
   `Option<[u8; 32]>` also works but breaks Statement's field uniformity.
2. **Fiat-Shamir**: absorb it in `Transcript::absorb_statement`
   (transcript.rs) after `focus_bound`, so prover and verifier bind the same
   root. This changes every proof's transcript — coordinate with the
   accumulator-size stabilisation (soft3 blocker 3) so the format breaks once,
   not twice.
3. **Verifier check** (`verify` in lib.rs, or a step emitted by
   `build_look_steps_from_trace`'s verifier-side twin): for every
   `LookOpening`, `root_from_leaves(&lo.leaves)` packed to bytes must equal
   `statement.bbg_root`. Equivalently as limbs:
   `root[i].as_u64().to_le_bytes() == statement.bbg_root[8i..8i+8]`.
   With that, the existing chain (root = r[4]/r[11]/r[12]/r[13] = object
   limbs) closes end-to-end: object root = recomputed root = public root.
4. **`commit()`**: reject (`CommitError::LookBinding`) if any opening's
   recomputed root disagrees with `statement.bbg_root` — same
   refuse-to-emit policy the other look bindings already follow. Note
   `commit()` does not currently take a `Statement`; either pass it in or
   check in `decide`/`verify` only.

## how look bindings consume it (caller side)

The bbg/nox caller flow becomes:

```rust
let root = state.root();                       // bbg — public input
let statement = Statement { bbg_root: root, .. };
// program object carries goldilocks_from_bytes32(&root) limbs (unchanged)
let provider = ProofLookProvider::new(&state); // bbg — records openings
let outcome = nox::reduce(...);
let openings = provider.take_look_openings(); // leaves = state.root_leaves()
let proof = zheng::commit(&trace, .., &openings, ..)?;
zheng::verify(&proof, &statement, &params)?;   // now checks root publicly
```

`bbg/rs/tests/look_e2e.rs` is the template; once Statement carries the root,
its "declare root in object" step stops being the only root anchor.

## non-goals

- No change to `RootLeaves`, `root_from_leaves`, or the register conventions —
  they already match bbg exactly.
- No bbg-side change: root exposure and wire serde are complete.
- Sizing: +32 bytes per Statement, one extra absorb, ≤ a few eq-steps per
  proof. No new CCS pattern; `pattern_look_inline` stays trivial.
