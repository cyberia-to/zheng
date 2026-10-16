---
tags: zheng, zk, whir, veil, research
crystal-type: process
crystal-domain: crypto
alias: small zero knowledge, G1, hiding WHIR
status: prototype measured, under review
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

the `SPEND` shape, measured (fixture `tests/common/spend.rs`: two inputs
with four record digests and a key each, commitment = three node calls,
owner check, nullifier, a secret depth-`d` path per input with secret
siblings and directions; two outputs of three node calls; balance with a
public fee; four `lt` range checks; two `data·token = pred` predicates):
depth 34 compiles under the shipped caps, 20,060 read columns at depth 40
(17,684 at 34) in a 2^15-column relation; the non-hiding proof of the same
relation and witness is 43,869 B (depth 40) / 44,221 B (depth 34). depth 40
exceeds the relation compiler's evaluation cap (`MAX_CALLS` = 4,096
formula evaluations); its figures below come from a local build with the
cap at 8,192, never committed — the cap is a finding for the `SPEND`
specification, not for G1.

before any hiding was built, the budget was therefore ≈ 20 KB over the
non-hiding proof at 2^15. any construction that adds
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

### attempt 0 — the literature as implemented elsewhere (rejected, measured by others)

Plonky3's HVZK-WHIR (PR #1767, after 2026/391): 3.28× the non-zk proof at
2^16, 3.04× at 2^18, at 100 bits; every mask a separate oracle with its own
Merkle paths at every query (≈ 120 KB fixed). Rejected before building:
any design that opens a second oracle at the round-0 queries pays ≈ q₀ ×
(path depth × 32 B) ≈ 38 × 17 × 32 ≈ 20 KB for the paths alone.

### attempt 1 — round-0 masking, one geometric `Ψ` point (failed: leaks one Fp3)

The design of § the design with `Ψ = eq(pow(z_ψ), ·)` on the block. The
exact linear-algebra test (lens `whir::zk::lemma`, whole tables, `k₀ = 4`,
`q₀ = 8`, `R = 256`) finds the block system one Fp3 short: rank `128 + 27`
of the needed `128 + 30`, and the off-block change is not matched.
Reason: the round-0 sumcheck's block contributions are tensors at two
points (`z_ψ^{16}`, `z_ood^{16}`) and telescope onto `T(P)` and `T(α)` at
each; `u_ψ`, `u` and the OOD answer lie in their span, so one combination
of revealed values cancels the block and is a function of the witness.
Kept as the regression test `a_geometric_block_weight_leaks`.

### attempt 2 — round-0 masking, uniform block weights `ξ` (veil-W, built)

`Ψ = Σ_y ξ_y·[· = y]` over the block, `ξ` from the transcript (one Fp3
coin per block slot). The same test solves for every seed (rank `128 +
30`, the one automatic relation being `σ_{k₀}`, fixed by `f_1`); at the
device shapes the block-restricted rank is exactly the lemma's (2^14:
622/638 by query count, 2^16: 638, 2^17 k = 5: 1,252; `lemma_prod`). The
prover runs the rank check on its actual coins (2–4 ms at 2^15) and
recommits on failure, so the zero-knowledge claim needs no bound on that
event.

With veil's layout the masking columns of the masked relation sat at
2^15, so every free half doubled; `Layout::compact` (drop every unread
column, not only the trailing ones) put the depth-34 SPEND back to 2^15:
51,536 → 47,056 B.

### attempt (b) — Libra masks + non-hiding WHIR + one small hiding commitment to the mask (rejected, estimated)

A non-hiding WHIR opening of the witness reveals `q₀·2^{k₀}` codeword
values of it (608 at 2^15) plus the folded words — the leak is the
witness's codeword, which no separately committed mask can cancel without
entering the same oracle. As stated it is not zero knowledge; made zero
knowledge, it is attempt 2. Its cost as stated would be the non-hiding
proof (43.9 KB) plus veil's hiding opening of the Libra masks alone
(unique-decoding Ligero, ≈ 123 columns: ≈ 40–60 KB at hundreds of entries,
`audit/zk-profile-2026-10.md` §3: 61.7 KB at 2,417 entries) ≈ 85–105 KB.

### attempt (c) — zk wrapper around a non-zk proof (rejected, estimated)

Proving "I know a non-zk succinct proof of `SPEND`" in a small masked
relation needs the WHIR verifier as a circuit. zheng's field-native
recursion circuit verifying one step takes 21,278–27,444 rows of 64-column
words (`audit/recursion-2026-10.md`), i.e. a ≈ 2^20-cell committed word;
the recursion audit's own estimate for one wrap opening at that size is
≈ 60–90 KB non-hiding, and the byte-transcript, binary-Merkle succinct
proof is costlier in circuit than the field-native one. Worse than
attempt 2 by ≥ 15 KB and by tens of seconds of proving.

### attempt (d) — other 2024–2026 constructions

- 2026/391 (Chiesa, Fenzi, Weissenberg): the asymptotically right answer
  (`1 + o(1)` oracle length); as compiled by Plonky3, attempt 0.
- 2024/1037 (Haböck, Al Kindi): the batching idea attempt 2 carries to
  WHIR's round 0.
- 2025/1354 ("Shred-to-Shine", FRI-based multilinear commitments): same
  shape as 2026/391 for this purpose (masks of the folded words as extra
  oracles).
- VEIL (2026/683): not readable from this machine (browser challenge), as
  in October; not evaluated.

## results

`SPEND` fixture, Apple M4 Max, 2026-10-16, **load average 62–66 throughout
(another stand's block aggregator on ten cores)**: medians of 5, times are
upper bounds of a quiet machine. veil and veil-W prove times include the
relation compile and the witness; the non-hiding column's do not. Verify
recompiles the relation from the statement (no cached key).

| statement | non-hiding (profile 1) | veil (Ligero) | veil-W |
|---|---|---|---|
| SPEND depth 40 (cap 8,192, local) | 43,869 B | — | **46,480–46,704 B** (dedup of queried leaves varies the size), prove 695 ms Metal / 782 ms CPU, verify 165–211 ms |
| SPEND depth 34 (shipped caps) | 44,221 B | 165,933 B | 46,288–46,800 B, prove 628 / 809 ms, verify 158–168 ms |
| node-merkle-32 (secret leaf) | 46,719 B (envelope) | 163,909 B | 42,144 B, prove 365 / 878 ms |
| hash.tri (secret preimage) | 16,791 B (envelope) | 63,205 B | 25,860 B, prove 125 / 87 ms |

Proven bits (lens `zk_terms` + veil's IOP): 128.08 with grinding, 112.08
without (WHIR rows); the combination row needs 13 grinding bits at 2^15.
Byte map of a depth-34 proof (46,736 B): round-0 openings 20,368 B (coset
values 4,864, `Ĝ` 912, salts 1,216, siblings 13,376), round-1 and final
openings 18,848 B, final polynomial 3,072 B, Spartan 3,768 B, the rest
680 B. The zero-knowledge cost over the non-hiding proof at the same size
is ≈ 2.2 KB (`Ĝ`, salts, `u_ψ`, `u`, the mask sums).

## open

- the relation compiler's evaluation cap admits two secret paths of depth
  ≤ 34; depth 40 needs the cap at ≥ ~5,000 evaluations or a secret-sibling
  level jet;
- measured on hemera 0.3 (8 + 16 rounds); hemera 0.4 (profile #15, 6 + 6
  full, 48 partial, `x⁷` every round) changes prover times and the node
  gadget's width, so the SPEND relation's read columns — 20,060 of 32,768
  at depth 40 — grow; bytes stay as long as the relation stays ≤ 2^15 with
  the masks (else 2^16: +≈ 3–5 KB, still ≤ 64 KB at the 2^16 floor of
  49.8 KB);
- no envelope profile: veil-W proofs travel as `ZHVEILW1` bytes beside a
  `PrivateStatement`;
- no held proving key yet (veil has one);
- the prover is not constant time (as veil).
