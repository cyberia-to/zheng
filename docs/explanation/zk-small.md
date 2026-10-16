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

## attempts

(filled in as they are measured)
