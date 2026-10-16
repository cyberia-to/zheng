---
tags: zheng, audit, zk, veil, whir, privacy, G1
crystal-type: audit
crystal-domain: crypto
date: 2026-10-16
---
# small zero knowledge (gate G1) — 2026-10-16

Gate G1 of soft3 `proposals/privacy-frozen.md` (§3, §5): a hash-only
zero-knowledge proof of `SPEND` of ≤ 64 KB at ≥ 128 proven bits (ROM,
grinding counted), post-quantum, prove ≤ 1 s on Apple silicon. Research
page with every attempt: [zk-small](../docs/explanation/zk-small.md).
Contracts: `specs/execution.md` § zk profile with a WHIR opening (veil-W),
`specs/soundness.md` rows veil-W, lens `specs/whir.md` § zero-knowledge
opening.

Stand `~/cyber/.stands/G1`: zheng `feat/zk-small` (off `release/0.4`
09308d7), lens `feat/zk-small` (off `release/0.2` e11eaa8), nox and joy
`release/0.4`, hemera and strata `main` (**hemera 0.3**: 8 full + 16
partial rounds), honeycrisp and tade `main`. Apple M4 Max, macOS 26.4,
`--release`. **The machine was shared: load average 60–90 during every
timing below (another stand's block aggregator held ten cores);** times are
medians and upper bounds of a quiet machine; sizes are deterministic per
seed and vary by a few hundred bytes across seeds (deduplicated queries).

## 1. verdict

**G1 is met by the prototype, pending merge review:** the `SPEND` fixture
of depth 40 proves in zero knowledge in **46,480–46,704 B** at 128.08
proven bits (112.08 without grinding), in 695 ms on Metal and 782 ms on
the CPU under load 62–66, against 165,933 B for veil on the depth-34
fixture (3.5× smaller). The zero-knowledge cost over the non-hiding proof
of the same relation is ≈ 2.2 KB. Depth 40 needs the relation compiler's
evaluation cap raised (§5); depth 34 runs on the shipped caps in 46.3–46.8
KB. The fallback, if review rejects the construction, is veil v1 as
reviewed (165 KB at this shape).

## 2. construction

veil's masked Spartan (masking rows, Libra masks on both sumchecks),
unchanged, with the hiding Ligero opening replaced by a zero-knowledge
WHIR opening (lens `whir::zk`):

1. `c ∈ F^{2^n}`: the read witness columns (compact layout), the Libra
   masks, and a uniform block `r` at the top `R` slots,
   `R = next_pow2(2^{k₀}·(q₀ + 3(1 + s₀)))` (1,024 at 2^15);
2. a uniform mask table `G` over the high `n − k₀` variables: the virtual
   word `g(X) = Ĝ(X^{2^{k₀}})` is constant on folding cosets, so a round-0
   leaf carries one extra Fp3 symbol; four salt limbs per round-0 leaf;
3. after Spartan: `ξ` (one Fp3 coin per block slot), `u_ψ = Σ ξ_k r_k`,
   `μ`; the claim `Λ = F' + μ·Ψ` where `F'` is veil's final functional with
   the mask slots' weight removed; `u = Λ(g)`; grinding; `β`; WHIR on
   `h = c + β·g` with value `V + μ·u_ψ + β·u`;
4. the prover checks the masking lemma's rank condition on its actual
   round-0 coins (lens `whir::zk::check`, 2–4 ms) and recommits with fresh
   `r`, `G`, salts on failure.

## 3. the zero-knowledge argument (HVZK simulator)

Interactive protocol, honest verifier, salted round-0 leaves in the ROM.
Where randomness enters: veil's pad fill, `g1`, `g2` (Spartan); `r`, `G`,
salts (the opening); the verifier's view is the Spartan messages, `u_ψ`,
`u`, the WHIR transcript (round-0 OOD answers, round-0 sumcheck values,
the opened round-0 leaves — coset of `c`, `Ĝ(y_j)`, salt — with their
siblings, every later root, OOD answer, sumcheck value, opened leaf and
sibling, the final polynomial), the grinding nonces.

Simulator: run the honest prover on any witness of the statement (e.g. a
fixed one). Indistinguishability by a measure-preserving bijection of the
prover's randomness for two witnesses `w`, `w'` at fixed coins:

1. veil's argument changes `(g1, g2, pad fill)` so that the Spartan
   transcript, hence `V = F'(c)`, is identical; it never reads the block;
2. `ΔG = −Fold(Δc)/β` keeps `f_1 = Fold(h)` identical: every message after
   round 0 and every later Merkle root coincide;
3. the remaining round-0 values are the `q₀·2^{k₀}` opened coset values of
   `c` and `E = 2 + s₀ + 2k₀` Fp3 messages, all linear in the block; when
   their reduction modulo the cosets has `F_p`-rank `3(E − 1)` (one relation
   automatic), a block change matches every off-block change (masking
   lemma); `Ĝ(y_j)` follows from the cosets; the prover outputs only such
   transcripts and the event depends on public coins only;
4. unopened round-0 leaves are hashed with 256-bit salts.

Distance: veil's `ε_v + 2/p³` plus `Q·2^-256`, plus the coins PRF's
advantage; zero knowledge in the ROM after Fiat–Shamir (BCS, eprint
2016/116). The first attempt (block weight at one geometric point) fails
step 3 by one Fp3 — found by the exact test, documented and kept as a
regression test.

## 4. ledger rows

`specs/soundness.md`: *veil-W — knowledge soundness* (`ε_IOP` veil's plus
`μ`; `|Λ|/p³` for `u_ψ`; lens `zk_terms`: WHIR's rows on `h`, the
two-word combination by `β` with `comb_pow` grinding — 13 bits at 2^15, 15
at 2^16, 17 at 2^17 — and `|Λ|²/|K|` for `u`): **128.08 bits with
grinding, 112.08 without** at 2^12…2^17; *veil-W — zero knowledge*
(argument above).

## 5. measurements

`audit/tools`-style runs of `examples/fast_path`; `p1-spend-*` = profile 1
on the same relation and witness (statement made public; prove time
without relation compile and witness), `veil-*` / `veilw-*` include them;
verify recompiles the relation from the statement.

| statement | backend | profile 1 | veil | veil-W bytes | veil-W prove | veil-W verify |
|---|---|---|---|---|---|---|
| SPEND depth 40 (cap 8,192) | Metal | 43,869 B, 324 ms | — | 46,704 | 695 ms | 211 ms |
| SPEND depth 40 (cap 8,192) | CPU | 43,869 B, 521 ms | — | 46,672 | 782 ms | 165 ms |
| SPEND depth 34 | Metal | 44,221 B, 225 ms | 165,933 B, 193 ms | 46,800 | 628 ms | 158 ms |
| SPEND depth 34 | CPU | 44,221 B, 508 ms | 165,517 B, 296 ms | 46,416 | 809 ms | 168 ms |
| node-merkle-32 | Metal | 46,719 B (envelope) | 163,909 B | 42,144 | 365 ms | 73 ms |
| hash.tri | Metal | 16,791 B (envelope) | 63,205 B | 25,860 | 125 ms | 23 ms |

Relation (SPEND): 32,768 columns, 17,684 read at depth 34 and 20,060 at
depth 40; committed `n = 15`, `R = 1,024`.

**Depth 40 and the compiler cap.** Two secret paths of depth 40 need more
than 4,096 formula evaluations (`relation::MAX_CALLS`); the fixture
compiles to depth 34 on the shipped cap. The depth-40 rows were measured
with a local build at `MAX_CALLS = 8,192`, not committed. A `SPEND`
specification needs the cap raised or a secret-sibling level jet.

Byte map of a depth-34 proof (46,736 B): round-0 openings 20,368 (coset
values 4,864, `Ĝ` 912, salts 1,216, siblings 13,376), later openings
18,848 (values 9,984, siblings 8,864), final polynomial 3,072, Spartan
3,768, `u_ψ`, `u`, OOD and sumcheck values 480, framing 200.

## 6. tests

| test | what |
|---|---|
| lens `whir::zk::tests` | completeness at five shapes, wrong `v`/`u`/nonce/weight/root, every round-0 symbol bound (coset, `Ĝ` limbs, salt limbs), bit-flip scan of a small opening (0 accepted), plain/zk commitments not interchangeable, zk bits ≥ 128 at the device shapes, the rank check passes uniform `ξ` and catches a geometric `Ψ` |
| lens `whir::zk::lemma` | exact linear algebra on whole tables: every round-0 message kept by a block change (uniform `ξ`); geometric `Ψ` one Fp3 short; below the size bound unsolvable |
| lens `whir::zk::lemma_prod` | block-restricted rank equals the lemma's at 2^14, 2^16, 2^17 |
| zheng `veil::small::tests` | secret-input proofs verify, OS coins differ, seeded proofs reproduce, statement binding, byte regions, layouts meet the bound |
| zheng `veil::small::zk_tests` | per-category chi-square (two witnesses `x`, `−x`, 40 proofs each) |
| zheng `tests/veil_w.rs` | statements bound, spliced proofs, weak/foreign parameters refused, bit-flip scan |

Bit-flip scan (`every_bit_flip_of_a_veil_w_proof_is_rejected`, `--ignored`):
25,540-byte proof, **204,320 flips, 0 accepted**, 691 s under load.

Statistical test (40 proofs per witness, chi-square 15 d.o.f., rejection
above 44.3), final code (uniform `ξ`, rank check, compact layout): every
category uniform and witness-independent — matrix evaluations 6.2/10.6
(two-sample 7.3), outer rounds 10.6/12.0 (16.3), inner 13.8/18.0 (8.9),
mask sums 11.9/11.5 (7.3), `u_ψ, u` 9.7/13.2 (17.0), round-0 OOD 13.9/12.8
(6.9), round-0 sumcheck 9.5/13.8 (11.1), round-0 coset values 11.1/13.1
(11.3), `Ĝ` 20.8/11.2 (17.7), salts 7.0/5.8 (7.4), round-0 siblings
7.7/11.4 (9.2), final polynomial 8.5/17.1 (15.0). The marginal test does
not see the geometric-`Ψ` leak (a linear relation between categories); the
exact tests of §6 do. This statement has no committed round after `f_0`.

## 7. self-review

- *Soundness, transcript order.* `u_ψ` is absorbed before `μ`, `u` before
  the grinding and `β`; the verifier recomputes `V + μ·u_ψ` itself and
  never reads a prover value for it; the round-0 leaf width, the `Ĝ` limbs
  and the salt limbs are authenticated with the coset; the weight's
  explicit entries enter the closing check through the final polynomial's
  hypercube table.
- *Compact layout.* drops columns no matrix reads; pinned columns are
  pinned as before; the verifier derives the same layout. veil's own
  layout is unchanged (its bytes and tests unchanged).
- *Mask slots.* no matrix reads them; the inner sumcheck's witness is `c`
  with them zero, fixed with the commitment; `F'` subtracts exactly their
  `eq(r', ·)` weight (block: one eq term; Libra slots: explicit).
- *Zero knowledge.* the first design leaked (one Fp3); the shipped one is
  checked exactly at the device shapes and on every proof by the prover.
- *Retry.* a failed attempt's block, `G` and salts are never reused (labels
  `W_RETRY + 3a`); `g1`, `g2` and the pad fill are reused — the discarded
  transcript is never output.
- *Not constant time* (as veil).

## 8. hemera 0.4

Everything above is on hemera 0.3. hemera 0.4 (profile #15: 6 + 6 full
rounds, 48 partial, `x⁷` every round) changes: prover and verifier times
(every Merkle leaf and node, the grinding, the coins PRF), and the node
gadget's width, so the SPEND relation's read columns grow. Bytes depend on
the hash's output length (unchanged, 32 B) and on the committed size `n`;
they stay as measured while the relation with its masks fits 2^15.

## 9. not done / open

- no envelope profile (`ZHVEILW1` bytes beside a `PrivateStatement`); no
  held proving key;
- the relation compiler cap for depth 40 (§5);
- no external review of the masking lemma.
