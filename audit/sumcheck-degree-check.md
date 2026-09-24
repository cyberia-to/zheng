---
tags: zheng, audit, cyber
crystal-type: report
crystal-domain: comp
---
# sumcheck round-polynomial degree check

date: 2026-09-24 · revision: origin/master 44bd5bf · property: launch #40 (a verifier
checks every argument it takes)

## finding

`SumcheckVerifier::verify_round` (`rs/src/sumcheck/verifier.rs`) checked only the
additive identity `g(0)+g(1) = current_claim`. It never checked the round
polynomial's `degree` field or its coefficient count against the degree the
protocol actually allows for that round. A polynomial of any degree satisfies
the additive identity for any claim — the identity constrains only two field
elements (`eval_0`, `eval_1`), so extra coefficients that sum to zero across
`x=0` and `x=1` are free. The standard soundness argument for sumcheck (a
random challenge distinguishes a dishonest continuation from the true one with
probability `1 - degree/|F|`, by Schwartz-Zippel) requires the degree to be
fixed in advance; without the check the verifier's own code carries no such
bound.

`consistency_check_alone_cannot_catch_an_overhigh_degree` (new,
`sumcheck/verifier.rs`) demonstrates the isolated gap directly: a degree-3
polynomial, checked against a verifier constructed for degree 1, passes the
additive-identity check unchanged.

`SpartanVerifier::verify_using` (`rs/src/spartan/verifier.rs`) — the crate's
own top-level verifier, called from `lib.rs::verify()` (every `TraceProof`:
tickets, fold, φ*), `folding/decide.rs`, and `ccs/particle.rs` — constructed
two `SumcheckVerifier`s (outer, inner) without ever supplying an expected
degree, so this gap reached the crate's real, shipped verification surface.

## honest caveat

`SpartanVerifier`'s transcript absorbs a round polynomial's `degree` and every
coefficient (`transcript.rs::absorb_sumcheck_poly`) before deriving the next
Fiat-Shamir challenge. Tampering with an otherwise-honest proof's `degree`/
coefficient count therefore already perturbs every challenge derived
afterward and breaks the proof's later numeric checks for an unrelated
reason — confirmed empirically: the naive post-hoc tamper this note first
tried (`spartan::verifier::tests::rejects_forged_round_polynomial_degree`)
was already rejected before this fix, not because of a degree check, but
because the perturbed transcript desynchronized `rho_x`/`eval_point` from
the values the rest of the honest proof was built against. This audit does
not claim a demonstrated forgery of a false statement through
`SpartanVerifier::verify` — constructing one, if possible at all, would
require building a self-consistent proof for a false witness from scratch,
not tampering with a true one, and is out of this slice's scope. The fix
closes the isolated gap on its own terms (the verifier's degree bound was
absent, full stop, matching the standard requirement and this crate's own
`execution/proof.rs::valid_polynomials` gate on its narrower CCS-relation
path) as defense in depth on the crate's main verification surface, at
negligible cost.

## fix

`SumcheckVerifier::new` takes a `max_degree: usize`; `verify_round` rejects a
polynomial whose `degree` or coefficient count does not match it.
`SpartanVerifier::verify_using` now derives the correct bound per instance:
outer rounds at `(max multiset arity) + 1` (matching
`OuterSumcheckProver::new`'s own `degree` field), inner rounds at the fixed
bilinear degree 2 (matching `SumcheckProver::round_poly`, always
`SumcheckPoly { degree: 2, .. }`). Both formulas are read directly off the
corresponding prover code, not re-derived independently.

## remains

- `rs/src/execution/proof.rs` (not yet on origin/master — an owner
  working-tree module) has its own, separately-implemented `valid_polynomials`
  gate ahead of its own call into `SpartanVerifier::verify_using`. Once that
  module merges, its gate becomes redundant with this one; harmless
  (`SpartanVerifier` now enforces the same bound unconditionally) but worth
  collapsing to one check at that point.
- Whether an unbounded-degree round polynomial is exploitable end-to-end
  against `SpartanVerifier::verify`'s Fiat-Shamir transcript (as opposed to
  the plain-interactive model the general sumcheck soundness argument
  assumes) is not resolved here either way; this fix removes the question
  rather than answering it.
