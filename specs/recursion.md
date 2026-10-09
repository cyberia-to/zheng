---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: recursive composition spec, proof recursion, IVC spec
---
# recursion

Incrementally verifiable computation over the nox machine
(`rs/src/recursion/`). The step relation of step `i` proves its nox
segment *and* that the verifier of step `i − 1` accepted: the verifier
runs inside the step's trace as the recursion circuit. A proof of any
number of steps is the last step's proof, the state it started from and
one decider — its size does not depend on the number of steps.

Constant size comes from this recursion, not from accumulation alone.
Accumulation (`accumulation.md`) turns many evaluation claims into one
decider, but every accumulation step leaves spot-check openings that
someone must verify; without a verifier inside the next step the proof
carries every step's openings and grows with the run
(`audit/accumulation-2026-10.md` §6). Here each step's openings are
checked by the next step's circuit and only the last step's travel.

## objects

- **parameters** (`Params`): WHIR parameters of every committed word, the
  step size `2^n` rows (`n = 15`), `ℓ = n + 6` variables per word, the
  accumulation configuration for four input words (`AccConfig::derive`
  with `m = 4`).
- **words**: Reed–Solomon codewords in WHIR's round-0 layout (lens
  `LeafLayout`) under a field-native hemera Merkle tree: a leaf is the
  duplex sponge (tag `LEAF`) over its symbols, a node is
  `perm(l ‖ r ‖ NODE_TAG ‖ 0⁷)[0..4]`. Same code, domain and distance as a
  lens commitment; only the hashing differs. The last accumulator is
  committed with lens (`Whir::commit_ext`) for the decider.
- **transcript**: an overwrite duplex sponge over hemera's permutation,
  rate 9 lanes (three Fp3), capacity 7 lanes with a domain tag; an Fp3
  item never straddles a block; challenges are output limbs (no byte
  reduction); an index is the low bits of a limb `v ≠ p − 1`
  (`p − 1 = 2^32·(2^32 − 1)`, so `v mod 2^k`, `k ≤ 32`, is exactly
  uniform); grinding absorbs a nonce and requires the low bits of the next
  limb to be zero.
- **state** (`StateV`): context digest, steps verified, chain of
  pre-committed roots, the first segment's first row and the last verified
  segment's successor (nox columns), the accumulator (root, `(ρ, v)`, OOD
  claims, spot claims `(ω^s, y)`), three deferred claims.

## the step relation

One AIR over `2^n` rows with three committed words of 64 columns:

| word | columns | committed |
|---|---|---|
| a | nox phase 1 (64) | before the run's challenges (pre-commit) |
| b | nox phase 2 (15) ‖ circuit phase 1 (49) | at the step |
| c | circuit phase 2 (54) ‖ zero (10) | after the circuit's challenges |

Constraints: the machine's (`machine.md`, with the run's memory
challenges) and the circuit's (below, with the step's `(α_V, β_V)`).

## the recursion circuit

Four row kinds over the 49 + 54 circuit columns:

- **ARITH**: four gates a row, `out = qm·x·(y + qs·z) + qa·x + qb·y +
  qc·z + qk` over Fp3, each a compute, an assertion (`out` unused, the
  value must be zero when `live`) or a free witness;
- **PERM**: a hemera permutation in four rows (input and states after
  rounds 0, 1; after rounds 2, 3 and the 16 partial-round inverses; after
  rounds 20–22; the output) — 160 constraints of degree ≤ 8; the input
  of a block is fixed by flags on the row before it: rate lanes kept,
  zeroed or bound to memory; capacity chained, fresh with a tag, or a
  Merkle node whose current digest comes from the previous output and
  whose direction bit is a memory read;
- **BITS**: a canonical 64-bit decomposition in four rows of 16 bits
  (`hi = 2^32 − 1 ⇒ lo = 0`);
- padding.

Every row has 17 memory slots: a slot reads (`+1`) or writes (`−reads`)
one Fp3 value at a fixed address; a logUp running sum over fingerprints
`α_V − (addr + β_V·value)` closes cyclically. A permutation block reads or
writes three lanes as one Fp3 (flag `WIDE`). The preprocessed columns —
selectors, gate coefficients, addresses, multiplicities, block flags, the
output row — are the circuit's key (107 columns); the public input is the
state digest at the output row (four columns `x_j·[row = out]`).

The program (`program::run`) is written once over `Ops` and run three
ways: natively by the final verifier, by the prover's own check, and by
the circuit builder, whose operation order fixes the layout. It absorbs
the previous state (free witness), runs the step verifier on the previous
proof, computes the initial state from the context's parts, selects
`live ? verified : initial` element by element, and hashes the result.
`live` is a column constant over the trace, 0 only in the base step:
every assertion (gate assertions, Merkle roots, grinding) is multiplied
by it, so the base step verifies a dummy proof and outputs the initial
state. A base step anywhere but the first restarts the chain from the
initial state; the final checks (step count = segments, chain = the
pre-committed chain) then fail.

## deferred claims

The step verifier never evaluates a constraint. After the zerocheck it
holds `G(point) = c` with

```text
point = (local[192], next[192], nox publics[31], key[107], public input[4],
         α_V, β_V, μ1, μ2, μ3)
G     = Σ_k μ1^{k mod B}·μ2^{⌊k/B⌋ mod B}·μ3^{⌊k/B²⌋}·C_k     (B³ ≥ #constraints)
```

and the publics it was sent must equal the public columns:
`Σ_j eq(γ_n, j)·nox_j(ρ ‖ bits(step)) ` over the run's global nox columns
(`n + 32` row variables, 5 column variables) and `Σ_j eq(γ_v, j)·K_j(ρ)`
over the key (`n` row and 7 column variables), `γ` drawn after the
publics are absorbed. Each kind is one polynomial fixed by the statement
(`G`, `P̄_nox`) or the parameters (`P̄_V`); the state carries one claim of
each and every step folds its new claim in along the line through the
two points: the prover sends the line polynomial at `2..=deg`, its values
at 0 and 1 are the two claimed values, a challenge `r` gives the new
point and value. The final verifier evaluates the three folded claims
once (`Relation::g`, `Public::eval` of the global columns, the sparse
key).

## step protocol (`step::verify`)

Transcript tag `STEP`:

1. the public input `x = H(state)`;
2. word a: root and OOD answers (points from the root alone, tag `PRE`;
   the chain `D` absorbs root and answers); word b: root, OOD; `(α_V,
   β_V)`; word c: root, OOD;
3. nox boundary in (79) and out (79), the circuit's first row (103);
4. `τ`, seeds; zerocheck (`n` rounds, degree 9); every column at `ρ` and
   at its successor, the publics at `ρ`; `c = claim / eq(τ, ρ)`;
5. `γ_n`, `γ_v`; the three line folds;
6. the shift reduction (`air/shift.rs`) of the three words to one point
   (`Σ ζ^w (a_w + β n_w)`, the last row's successor the boundary), the
   three values; boundary claims at row 0;
7. boundary continuity (`b_in = b_last` unless the first step), the
   accumulation step over `(accumulator, a, b, c)` — `accumulation.md`
   with instances not re-absorbed (the transcript binds them), positions
   never deduplicated (every spot check opens its leaf in all four words
   with a full path), spot points kept as `ω^s`.

## IVC (`ivc::prove_run`, `ivc::verify`)

```text
pre       commit every segment's word a → D; (α, β) = H(statement, D);
          nox phase 2 of every segment
step i    circuit: verify step i−1 from state_{i−1} (base: none) → state_i;
          prove segment i ‖ circuit with public input H(state_i)
proof     state_{S−1}, step S−1's proof, the decider of its accumulator
verify    step S−1 natively → state_S; ctx, chain = D, step = S, the cyclic
          boundary; the three deferred claims; the decider
```

`verify(verify(π))`: a two-step proof is accepted only if the second
step's circuit accepted the first step's proof (`tests/recursion.rs`).

## soundness

Ledger rows: `soundness.md` § recursion. Every challenge is over Fp3;
every round is ≥ 128 bits with grinding priced in
(`params::tests::every_ledger_row_of_the_recursion_profile_reaches_128_bits`).
The composition of the step relation with the verifier it contains rests
on hemera behaving as a random oracle *inside* the circuit (the
Fiat–Shamir transcript of step `i − 1` is recomputed by step `i`); no
proof of recursive Fiat–Shamir knowledge soundness is claimed — the row
is conjectured, as for every deployed recursive proof system.

## not built

- the decider inside a step (decider-as-relation): the final proof keeps
  one native WHIR opening;
- a wrap step proving the final verifier with a small non-accumulating
  proof (the route to ≤ 64 KB, `audit/recursion-2026-10.md`);
- an envelope profile for recursive proofs.
