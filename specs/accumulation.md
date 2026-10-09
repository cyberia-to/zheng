---
tags: zheng, accumulation, warp, arc, whir, spec
crystal-type: entity
crystal-domain: crypto
alias: accumulation, accumulate, decider
---
# accumulation

Hash-based accumulation of evaluation claims on Reed–Solomon codewords,
and its decider (`rs/src/accumulate/`). It replaces `folding` (HyperNova
over hemera, unsound: the fold was never checked — `decider.md`).

## objects

All words of one accumulation live in the code `C = RS[K, L, 2^ℓ]` of
WHIR's round-0 layout for parameters `whir` and `ℓ` variables
(lens `specs/whir.md` § commit): `L` the order-`2^{ℓ+r}` subgroup of
Goldilocks, rate `ρ = 2^{-r}`, `K = Fp3`, symbol `s` = `f̂(ω^s)`, leaves
= folding cosets. A word committed with `Whir::commit` (base symbols) or
`Whir::commit_ext` (Fp3 symbols) is a word of `C`.

- **claim** `(z, y)`: the message multilinear `f` of the word (monomial
  coefficients of `f̂`) satisfies `f(z) = y`, `z ∈ K^ℓ` in lens order. An
  in-domain value `û(x) = y` is the claim `(pow(x), y)`, `pow(x) =
  (x, x², x⁴, …)`.
- **instance** `(root, ext, claims)`; relaxed relation `R̃_δ`: the
  committed word is `δ`-close to a codeword whose message satisfies every
  claim; strict relation: it is such a codeword.
- **accumulator**: an instance with Fp3 symbols and exactly `1 + s + t`
  claims (`AccConfig::acc_claims`).

`δ` and the list bound are those of the regime lens derives for WHIR's
round 0 at `(whir, ℓ)`: Johnson(μ) `δ = 1 − (1 + 1/(2μ))√ρ`, list
`≤ μ/ρ` (WHIR Theorem 4.3), or unique decoding `δ = (1−ρ)/2 − 1/n`, list
1 — so the decider's opening certifies the same distance the steps reason
about.

## a step (`accumulate` / `verify_step`)

Inputs: `m` instances `(u_i, C_i)` (any mix of accumulators and fresh
words), all over `C`. Transcript order:

1. absorb `"zheng-acc-step-v1"`, `m`, every instance (root, ext, claims);
2. `γ ← K`; claim `e` (numbered across inputs) gets weight `γ^e`;
   `w_i = Σ_{e ∈ C_i} γ^e eq(z_e, ·)`, `σ = Σ_e γ^e y_e`;
3. sumcheck `Σ_b Σ_i w_i(b) f_i(b) = σ`, `ℓ` rounds of degree 2, low
   variable first, messages `h(0), h(2)`; point `ρ`;
4. prover sends `μ_i = f_i(ρ)`, absorbed; verifier checks
   `Σ_i w_i(ρ) μ_i` equals the last claim;
5. grinding `comb_pow(m)` bits, `r ← K`, coefficients `r^{i}`;
6. prover commits `g` (honestly the table `Σ r^i f_i`, Fp3), root
   absorbed;
7. `s` OOD samples `ζ_j ← K`, answers `ĝ(ζ_j)` absorbed;
8. grinding `query_pow` bits, `t` symbol positions `x_k ← L` (exactly
   uniform, lens `squeeze_indices`); every input word is opened at the
   leaves holding them (one deduplicated Merkle multi-opening per word);
9. output accumulator: root of `g`, claims `(ρ, Σ r^i μ_i)`,
   `(pow(ζ_j), ĝ(ζ_j))`, `(pow(x_k), Σ_i r^i u_i(x_k))`.

The output's size and claim count are independent of `m` and of every
earlier step; its distance parameter is the input's.

## decider (`decide` / `verify_decider`)

`γ ← K`; sumcheck reduces the instance's claims to `f(ρ*) = v*`;
`v*` absorbed; one WHIR opening of the word at `ρ*` (`Whir::open` /
`verify_ext` for an accumulator) on a lens transcript seeded by a squeeze
of the accumulation transcript.

## what was implemented, against the papers

- **ARC** (Bünz–Mishra–Nguyen–Wang, eprint 2024/1731, §6 Construction
  6.3) accumulates RS proximity claims by a combined word, OOD samples and
  in-domain queries, and turns the in-domain answers into *quotient*
  constraints with degree correction (`Combine`, Lemma 3.9) and a `Fill`
  message; its NP accumulation (§7) carries two oracles.
- **WARP** (Bünz–Chiesa–Fenzi–Wang, eprint 2025/753) avoids quotients:
  the in-domain and OOD answers stay as multilinear evaluation claims
  carried by the accumulator (§2.4, Construction 7.2 "codeword
  batching"), and the claims of several words are batched by a sumcheck
  before the words are combined (§6 "twin constraint pseudo-batching").
- **This implementation** is WARP's claim-carrying structure instantiated
  for Reed–Solomon codes: the claims are evaluation claims on the
  message multilinear (WHIR's view of an RS word), out-of-domain samples
  are univariate (`ĝ(ζ)`, as in ARC §2.1 and WHIR) instead of WARP's
  multilinear-extension samples of the codeword, the words are combined
  with the powers generator `(1, r, …, r^{m−1})` in one round instead of
  WARP's `log m`-round affine-line pseudo-batching, and the claims are
  carried (no WARP §8 multilinear-constraint batching: `1 + s + t` claims
  ride in the accumulator and the next step's sumcheck batches them).
  Neither paper's construction is implemented verbatim; the round-by-round
  argument below composes the papers' lemmas for this protocol.
- Why not ARC verbatim: its quotient step needs a per-step Fill message
  and an FFT over Fp3, the NP variant carries two oracles, and its
  Johnson-regime proximity error (BCIKS20 as restated in ARC Definition
  3.7) is weaker than the mutual-correlated-agreement bound lens already
  relies on; the claim-carrying form lets the existing multilinear WHIR
  opening be the decider with no adapter.

## soundness

Round-by-round, every challenge over `K = Fp3` (`|K| = p³`,
`log2|K| = 191.99999999904`). `Λ = Λ(C^m, δ)`, the list of tuples of
codewords agreeing with `(u_1..u_m)` on a common `(1−δ)`-fraction;
`|Λ| ≤ μ/ρ` (WHIR Theorem 4.3 with Lemma 4.4: the interleaved RS code has
the RS code's Johnson list size). State function (as in WARP Lemmas 6.6
and 7.3): *some tuple in `Λ` satisfies every input claim*.

| round | error | source |
|---|---|---|
| `γ` | `|Λ|·(J − 1)/|K|` | for each tuple of `Λ` failing some claim, `Σ_e γ^e (v̂(z_e) − y_e)` is a nonzero polynomial of degree `≤ J − 1` in `γ`; union over `Λ` |
| sumcheck round | `|Λ|·2/|K|` | sumcheck (Lund–Fortnow–Karloff–Nisan) per tuple, union over `Λ` |
| `μ_i` check | 0 | for each surviving tuple some `v̂_i(ρ) ≠ μ_i` |
| `r` | `ε_mca(m−1) + |Λ|·(m−1)/|K|`, minus `comb_pow` | BCGM eprint 2025/2051 Lemma 9.3 (powers generator, degree `d = m−1`, Definition 9.1 error `d·(μ+½)^7/(3ρ^{3/2})·n²/|K|` up to `1 − (1+1/(2μ))√ρ`; unique decoding: `(m−1)·n/|K|`, WHIR Theorem 4.8 with Corollary 4.11) gives mutual correlated agreement, so `Λ(C, Σ r^i u_i, δ) = {Σ r^i v_i : v ∈ Λ}` except with that error (the argument of WHIR Lemma 4.13 with BCGM Definition 3.14); for each tuple `Σ r^{i}(v̂_i(ρ) − μ_i)` is a nonzero polynomial of degree `≤ m−1` |
| OOD | `(|Λ_1|²/2)·(2^ℓ/|K|)^s` | WHIR Lemma 4.25 |
| positions | `(1 − δ)^t`, minus `query_pow` | WARP Lemma 7.3 `ε_shift`: the unique codeword left after OOD differs from `Σ r^i u_i` on more than a `δ` fraction |

The output state is the same predicate at the same `δ`: distance is
preserved (WARP §2.4, Lemma 7.3), so steps compose without a depth bound.
`AccConfig::derive` picks `s`, `t`, `query_pow`, `comb_pow(m)` (≤ 32)
for 128 bits at the configured `m` and `J`, and `terms(m, J)` lists every
row above with its bits.

The decider adds the `γ` and sumcheck rows with `m = 1` and WHIR's own
round-by-round bound at `(whir, ℓ)` for an Fp3 word (lens `security_bits`,
≥ 128 by the profile policy).

**Fresh words.** Every word committed by a prover outside a step (the AIR's
phase-1 and phase-2 words, a CCS statement's witness) answers
`fresh_ood(whir, ℓ)` out-of-domain samples right after its root is
absorbed, before any challenge it feeds (WHIR Lemma 4.25, as in WHIR
Theorem 7.5's commitment phase): except with `(|Λ|²/2)(2^ℓ/|K|)^s ≤ 2^-128`
at most one codeword of its list agrees with the answers, so the later
rounds that read the word (zerocheck, column reduction, logUp, Spartan)
reason about one codeword and carry no list factor. The answers are
claims of the word's instance.

**Composition.** A proof is one transcript: AIR rounds, `S` steps, one
decider. Without grinding (the interactive protocol) every round is below
`2^-128` except the two ground ones: the combination round errs with up
to `2^{-(128 − comb_pow(m))}` and the positions round with up to
`2^{-(128 − query_pow)}`; the interactive total is at most the sum over
rounds (linear in the number of steps), dominated by those two terms per
step. The `2^-128` per round holds only with grinding priced in, i.e. in
the random-oracle model: non-interactively (Fiat–Shamir with hemera as a random oracle) a
prover making `Q` hemera queries succeeds with probability
`≤ Q·2^-128` plus Merkle-binding (hemera collision) terms — independent
of the number of steps (Canetti et al. 2019: round-by-round soundness
gives Fiat–Shamir soundness; for the reduction-to-accumulation setting,
WARP Appendix B: round-by-round knowledge soundness implies straightline
state-restoration knowledge soundness).

## size and work

A step sends `2ℓ + m + s` Fp3 elements, one root, two nonces and `m`
multi-openings of up to `t` leaves. The verifier reads `t` leaves of every
input word: an accumulation proof is linear in the number of words it
folds. Constant-size proofs of unbounded computations need the step's
verifier to run inside the next step's relation (recursion); that is not
built (`audit/accumulation-2026-10.md` § not done).
