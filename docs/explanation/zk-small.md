---
tags: zheng, zk, whir, veil, research
crystal-type: process
crystal-domain: crypto
alias: small zero knowledge, G1, hiding WHIR
status: in progress
date: 2026-10-16
---
# small zero knowledge — gate G1

the question (soft3 `proposals/privacy-frozen.md` §5, gate G1): a hash-only
zero-knowledge proof of the `SPEND` relation — two Merkle paths of depth 40,
a u64 value balance, two small nox predicates — of ≤ 64 KB at ≥ 128 proven
bits (random-oracle model, grinding counted; the figure without grinding is
stated beside it), post-quantum, proven in ≤ 1 s on Apple silicon.

where it starts (2026-10-16, `audit/fast-path-2-2026-10.md`): veil, the zk
profile, proves a secret-leaf membership of depth 32 in 165–181 KB; the
non-hiding succinct profile proves the same shape in 46.7 KB. the
difference is structural — veil's opening is a hiding Ligero-style tensor
test in the unique-decoding regime (≈ 123 sampled columns, ≤ 1 bit per
query), and parameter tuning buys ≤ 5.4 %.

this page records every attempt, including the failed ones, with numbers.
the audit of the chosen design is `audit/zk-small-2026-10.md`.

## literature

- **Chiesa, Fenzi, Weissenberg, "Zero-Knowledge IOPPs for Constrained
  Interleaved Codes", eprint 2026/391.** an honest-verifier zk variant of
  WHIR composed from zk interactive oracle reductions: a zk sumcheck with
  sublinear masks, a zk code-switching round, a masked base case. overhead
  `1 + o(1)` in oracle length. the full text was not reachable from this
  machine (the eprint server answers with a browser challenge); the
  construction steps and section numbers below come from the Plonky3
  tracking issue (Plonky3#1590) and its implementation PR (Plonky3#1767).
  **measured there** (KoalaBear, 100-bit target, k = 4): proof size 3.28×
  the non-zk WHIR at 2^16, 3.04× at 2^18 — "a fixed ~120 KB of mask
  spot-check openings", because every mask is a separate oracle with its
  own Merkle paths at every query. at our 128-bit target that construction
  as implemented there lands above veil's size, not below 64 KB.
- **Haböck, Al Kindi, "A note on adding zero-knowledge to STARKs", eprint
  2024/1037.** randomise each committed polynomial with enough random
  high coefficients that the opened evaluations are uniform (t-wise
  independence of a random polynomial of degree ≥ t evaluated at t
  distinct points), and batch a fully random polynomial into the FRI
  combination so every later layer is a function of a uniform word.
  this is what Plonky3's `HidingFriPcs` does.
- **Ben-Sasson, Chiesa, Spooner, "Interactive Oracle Proofs", eprint
  2016/116.** the BCS transformation keeps honest-verifier zero knowledge
  when Merkle leaves are salted.
- **Libra, eprint 2019/317 §4.1.** sum-of-univariates masks for the
  sumcheck; veil uses them.
- **WHIR, eprint 2024/1586**; mutual correlated agreement up to Johnson:
  Bordage–Chiesa–Guan–Manzur eprint 2025/2051, Haböck eprint 2025/2110 (as
  in `lens/specs/whir.md`).

## the floor, measured

the non-hiding succinct profile at the device parameters (rate 1/64, k = 4,
16 grinding bits, 128.08 proven / 112.08 without grinding), CPU, this
stand, 2026-10-16:

| committed vars | proof bytes (no statement) |
|---|---|
| 2^16 (synthetic) | 49,805 |
| 2^17 (synthetic, k = 5) | 57,901 |

a `SPEND` of two depth-40 node-jet paths, its record hashes as node calls,
the balance and two small predicates is estimated at 30–45 k free wires,
i.e. 2^16 committed variables. so a zero-knowledge `SPEND` proof ≤ 64 KB
needs the hiding to cost ≤ ~14 KB over the non-hiding proof at 2^16, or ≤
~6 KB if the masks push the witness to 2^17. any construction that adds
oracles with their own Merkle paths (2026/391 as implemented in Plonky3,
+120 KB at 100 bits) is out before it starts; the masks must ride in the
oracles WHIR already opens.

WHIR schedule at 2^16 (lens `WhirConfig`): round 0 folds 4 variables,
38 queries, 1 OOD sample; round 1 folds 4, 26 queries, 1 OOD; final
polynomial of 2^8 coefficients.

## the design: mask only round 0

**observation.** after the first folding round every WHIR message is a
deterministic function of the folded word `f_1 = Fold(f_0, α_1..α_k)` and
of public coins. if `f_1` is uniformly random among the words consistent
with what round 0 revealed, rounds 1…M need no masking at all, and their
Merkle trees need no salt. this is the Haböck–Al Kindi observation for
FRI (one uniformly random word batched into the combination) carried to
WHIR's sumcheck-folded round 0.

**construction** (envelope profile 2, call it veil-W):

1. the committed vector `c ∈ F_p^{2^n}` holds, at disjoint slots, the free
   witness of veil's masked relation, the two Libra masks `g1`, `g2`, and
   a block `r` of `R = 2^ρ` uniform values at the top `R` slots (top
   `n − ρ` index bits all one). Spartan treats every mask slot as an
   unread padding column (its value enters no matrix row);
2. `G ∈ F_{p³}^{2^{n−k}}` uniform; the virtual word `g(X) = G(X^{2^k})` is
   constant on every folding coset, so a round-0 leaf carries one extra
   Fp3 symbol `G(y)`; every round-0 leaf carries a 4-limb salt;
3. Spartan as veil (masking rows, Libra on both sumchecks); its final
   claim is one functional `F'` of `c` that gives zero weight to the
   `r` block (the inner sumcheck runs on `c` with the mask slots zero, and
   `F'` subtracts their `eq(r', ·)` weight);
4. the verifier draws a point `z_ψ`; the prover sends `u_ψ = Ψ(c)`, the
   univariate evaluation of the `r` block at `z_ψ` (in WHIR's weight form,
   `eq(pow(z_ψ), ·)` restricted to the block); the verifier draws `μ`; the
   claim functional is `Λ = F' + μ·Ψ`;
5. the prover sends `u_G = Λ(g)`; the verifier draws `β`; WHIR runs on the
   virtual word `h = c + β·g` with the claim `Λ(h) = (λ·g1_at + c2) + μ·u_ψ
   + β·u_G`. a round-0 query opens `c`'s coset, `G(y)` and the salt, and the
   verifier forms `h`'s coset itself.

**why it hides** (honest verifier, the interactive protocol; salted
round-0 leaves in the ROM; the full argument and its ledger row in
`specs/soundness.md` § zk rows and `audit/zk-small-2026-10.md`). fix the
coins. for two witnesses, veil's Spartan argument already gives a
measure-preserving change of `(g1, g2, pad fill)` that makes the Spartan
transcript identical. it remains to change `(r, G)` so that every PCS
message is identical too:

- `ΔG = −Fold(Δc)/β` makes `Δf_1 = 0`, so rounds ≥ 1 coincide;
- every round-0 message is then a linear form in `Δc`; on the `r` block,
  write `r`'s univariate as `Σ_j X^j ρ_j(X^{2^k})` (`j` = the `k` folded
  bits, `deg ρ_j < D = R/2^k`). a coset reveal at `y` is `(ρ_j(y))_j`
  (an invertible map of the coset's values); every other round-0 message
  — `u_ψ`, `u_G`, the OOD answers, the `2k` sumcheck values — has an `r`
  part `Σ_j κ_j·ρ_j(w)` at one of the `1 + s_0` points `w ∈ {z_ψ^{2^k},
  z_ood^{2^k}}`, because `F'` gives the block zero weight and the only
  constraints that reach it are geometric (`pow`) points;
- **masking lemma.** if `D ≥ q_0 + 3(1 + s_0)`, the points `w` lie in
  `F_{p³} ∖ F_p` and are pairwise non-conjugate, and the coefficient
  vectors `(κ_{e,w})` of the `E = 2 + s_0 + 2k` Fp3 messages are linearly
  independent over `F_{p³}`, then for every `Δ` outside the block there is
  a `Δr` that leaves every round-0 message unchanged. proof: fix the `q_0`
  coset values per `j` by interpolation; the rest of `ρ_j` is `Z·σ_j`,
  `Z = Π(Y − y_t)`, `deg σ_j < D − q_0`; by CRT over the `1 + s_0`
  degree-3 minimal polynomials, `(σ_j(w))_{j,w}` takes every value in
  `F_{p³}^{2^k(1+s_0)}` (`Z(w) ≠ 0` since `w ∉ F_p`); the messages are
  `F_{p³}`-independent linear forms in that vector.

**cost at 2^16.** `q_0 = 38`, `s_0 = 1`, `k = 4`: `D ≥ 44`, so `R = 1024`
mask slots; per round-0 leaf `+24 B (G) + 32 B (salt)`: ≈ 2.2 KB, plus
`u_ψ`, `u_G` and veil's two mask sums. predicted ≈ 52 KB for a 2^16
relation.

## attempts

(filled in as they are measured)
