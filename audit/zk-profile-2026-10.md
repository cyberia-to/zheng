---
tags: zheng, audit, zk, veil, state, verifying-key
crystal-type: audit
crystal-domain: crypto
---
# zk profile, state binding and verifying keys — 2026-10-09

Work package G of the proof-system repair (soft3
`proposals/proof-system-repair.md`, §3 rule 6, §5 phase 4): (1) two state
v3 binding gaps closed inside zheng, (2) cached verifying keys, (3) the zk
profile (envelope profile 2, scheme `veil`). Contracts: `specs/execution.md`
§ authenticated-state profile v3, § verifying keys, § zk profile; bounds:
`specs/soundness.md`.

Stand: zheng `feat/zk-and-state-binding` on `feat/succinct-profile` (9d53235),
joy `feat/zk-and-state-binding` on `feat/succinct-profile` (e2243f7; tested
merged with `feat/no-legacy`, which this joy branch needs to build against
bbg `feat/sound-proof-consumers`), bbg and cybergraph `feat/sound-proof-consumers`,
lens aee14d9 (`perf/batched-merkle`), hemera cf28a64 (`perf/permutation-neon`).
Machine: Apple M4 Max, 16 cores, rustc 1.95.0, `--release`. **The machine was
shared with other agents (load average 22–27 at the time of the final runs);
times are medians under that load. Proof sizes vary by a few hundred bytes
between proofs (deduplicated column openings and Merkle siblings).**

## 1. state v3 binding

| gap | before | after |
|---|---|---|
| `state_root` bound only if the caller authenticated every read under it | `verify_certificate(cert, &mut lookup)`: the callback "MUST" answer from a certificate the caller verified | `verify_certificate(cert, &StateEvidence)`: zheng folds the 14 leaves to the statement's own root (`compress4`), checks every carried table against its leaf (Brakedown commitment of the padded fields, length in the header), answers each read from the tables; same for `verify_v1`, `succinct::verify_state`, `Envelope::verify(Some(&evidence))` |
| `context` unbound by the v3 certificate | 32-byte field in `StateStatement`, absorbed by v1 and succinct transcripts, ignored by v3 | removed. Consumers: joy `JOYST002` compared it with `hemera(format, program name, source hash)` — labels of a disclosed witness, which anyone can re-certify under any context, so no relation can bind them; cybergraph and bbg passed constants. The v1 transcript's context is an explicit argument of `verify_v1` / `transcript_bytes_v1`, so `JOYST001` artifacts keep verifying |

Tests (zheng): `state_v3_tests::wrong_state_root_is_rejected` (every root limb,
evidence of another state, a statement re-rooted to it, a noncanonical limb),
`an_unauthenticated_read_is_rejected_by_zheng_alone` (evidence without the
table, a table altered under the honest leaves, a leaf altered to match it,
the same execution certified on altered state), `state_evidence::tests`
(bbg's frozen root vectors; forged value, appended zero with and without the
header fixed, version, moved namespace, leaf, duplicate table, noncanonical
leaf — all rejected), `tests/succinct_state.rs` (the same for the succinct
state path), `attack_fixtures::fixture_wrong_state_root_is_rejected` (no
evidence, evidence of another state). bbg `look_e2e::zheng_and_bbg_agree_on_the_root`
(a real state: zheng's root of the evidence = `StateCertificate::root` =
`BbgState::root`). There is no context to test.

## 2. verifying keys

`tests/verifying_key.rs`, hash.tri (7) on the shipped succinct choice (WHIR
1/64, k = 4, 24 grinding bits), 31 repetitions, median:

| | ms |
|---|---|
| verify without a key (compile + digest + verify) | 7.543 |
| verify with a cached key | 1.523 |
| derive a key: compile + digest | 6.081 |
| of which relation compile | 3.568 |
| `program_key` of a statement | 0.031 |

The digest is the hemera tree root over 1024-byte leaves of the LEB128
relation encoding (16,980 matrix entries at hash.tri). A plain sponge over a
fixed-width encoding cost ~19 ms (measured during development: 272 KB at
~16 MB/s through `hemera::Hasher`); batched leaves and the compact encoding
bring it to ~2.5 ms. The uncached path is therefore ~2.5 ms slower than
before keys existed (the digest binds the proof to its relation); a cached
key removes both compile and digest.

Tests: `vk::tests` (a derived key verifies every statement of its program and
shape; keys for another program or another input count are rejected; a key
naming this program but carrying another relation changes the digest and the
succinct proof fails; an altered digest fails), `veil::tests::keys_must_be_derived_for_the_statement`.

## 3. zk profile (veil)

Construction (`specs/execution.md` § zk profile): Spartan over Fp3 on the
statement's relation plus masking rows, both sumchecks masked with Libra
polynomials, the free witness half and both masks under one hiding
Reed–Solomon tensor commitment (Ligero geometry: `k` padding coefficients per
row with `k > t`, masking rows `m_a`, `m_b`, `m_P`, four salt limbs per leaf),
and one zero-knowledge linear test carrying every final claim.

Property (`specs/soundness.md` § zk rows): honest-verifier **statistical**
zero knowledge of the interactive protocol with salted leaves in the random
oracle model, distance `≤ ε_v + 2/p³ + Q·2^-256` with `ε_v ≤ types·log m/p`
(`50/p = 2^-58.4` at the fixture), and zero knowledge in the ROM after
Fiat–Shamir (BCS16, eprint 2016/116). Lineage: Libra (eprint 2019/317, §4.1)
for the sumcheck masks, Ligero (Ames–Hazay–Ishai–Venkitasubramaniam, CCS 2017)
for the hiding commitment and linear test. **VEIL (eprint 2026/683) is not
what is implemented**: its full text was not reachable from this machine
(publisher challenge page), so the construction is the standard zk-sumcheck +
masked-PCS one the work package allowed. WHIR has no zk variant in lens.

Fixture: hash.tri's hash (`hemera(x, 0⁷)`, the same formula) with the
preimage a secret input: `[2 [[3 [[16 [[1 0] [1 0]]] [0 1]]] [1 HASH]]]`.
The public profile on the same formula with `x` public gives the same digest
(checked in the test). Masked relation: `log m = 10`, outer degree 8, `ℓ = 11`,
`t = 5`; committed entries 2,417 (`2^ℓ` = 2,048 + outer mask `10·9·3` = 270 +
inner mask `11·3·3` = 99); commitment `k = 128`, 19 data rows (+3
masking), `N = 2^13` (rate 1/32 of `K = 256`), 123 sampled columns, 16
grinding bits. Proven bits: opening 128.24, masked IOP 185.1 → **128.2**.

`tests/veil_profile.rs`, 11 proofs:

| | veil | MITH (`ZHMITH01`, same statement, same binding) |
|---|---|---|
| proof bytes | 63,861 median (63,125 … 64,901) | 8,884,423 (varies with the challenges; 8.88–9.12 MB over runs) |
| envelope bytes | 64,840 (one proof) | 8,884,619 |
| prove | 142.9 ms | 7,318.5 ms |
| verify (no key) | 9.985 ms | 3,062.9 ms |
| verify (cached key) | 4.132 ms | — |

Size breakdown of one 64,309-byte proof: Spartan 2,616 (outer 1,920, inner
528, evaluations 120, mask sums 48); opening 61,693 — linear polynomial 9,192
(`3k − 1` Fp3), proximity polynomial 6,144 (`2k` Fp3), 122 opened columns ×
22 rows = 21,472, salts 3,904, 653 Merkle siblings 20,896. Verify time split
(one run, cached key): Spartan rounds and the pinned part 0.92 ms, the final
weight 0.25 ms, the opening 3.8 ms.

joy CLI, `rs/tests/fixtures/hash.tri --input-values 7`:

| | artifact bytes | prove | `joy verify` wall |
|---|---|---|---|
| `joy prove --zk` (veil) | 64,902 | 105 ms | 0.01 s |
| `joy prove --mith` | 8,992,569 | 5,994 ms | 2.44 s |

Bit-flip scan (`every_bit_flip_of_a_zk_envelope_is_rejected`, `--ignored`):
64,840-byte envelope, **518,720 flips, 0 accepted**, 444 s on 16 threads under
load.

Statistical test (`veil::zk_tests`, x·x with witnesses `12` and `p − 12`, 40
seeded proofs each, top-4-bit buckets, chi-square 15 d.o.f., rejection above
44.3):

| revealed | values per witness | χ² uniform (x / −x) | χ² two-sample |
|---|---|---|---|
| matrix evaluations | 360 | 18.7 / 14.7 | 16.5 |
| outer rounds | 1,440 | 13.1 / 26.9 | 24.0 |
| inner rounds | 1,680 | 30.8 / 18.9 | 17.0 |
| mask sums | 240 | 10.7 / 12.9 | 13.9 |
| proximity polynomial | 30,720 | 20.6 / 11.9 | 13.4 |
| linear polynomial | 45,960 | 17.6 / 5.2 | 10.5 |
| opened data columns | 9,774 | 11.6 / 14.8 | 10.9 |
| opened masking columns | 14,661 | 10.0 / 17.1 | 15.5 |

This is evidence, not the argument: it checks marginal uniformity of each
category and equality of distributions between two witnesses; the
zero-knowledge argument is the ledger row.

Other tests: `veil::hiding::tests` (openings at four shapes; forged value,
`μ`, proximity and linear coefficients, value with a compensating
coefficient, column, salt, sibling, nonce — all rejected; ≥ 128 bits and
`k > t`), `veil::libra::tests` (mask rounds, sums and committed weights
against brute force), `veil::pad::tests` (masked relations satisfied for
every mask, a wrong `t = s^7` rejected), `veil::tests` (completeness with
secret inputs, statements identical for `x` and `−x`, seeded proofs
reproduce and OS proofs differ, forged outputs/inputs/cycles/budget/shape,
proofs of other statements and other programs, foreign and forged keys,
byte tampering in every region, truncation and extension, every in-range
parameter set ≥ 128 proven bits and out-of-range sets refused, an
unsatisfying witness refused by the prover), `tests/veil_profile.rs`
(agreement with the public profile and with MITH, envelope binding of the
context and the statement, scheme byte).

## suites

| suite | result |
|---|---|
| zheng default (`cargo test --release`) | 248 passed, 0 failed, 3 ignored (2 before, plus the zk bit-flip scan, run above) — 225 passed before this work |
| zheng `--features serde` | 252 passed, 0 failed, 3 ignored |
| joy workspace (merged with `feat/no-legacy`, `--locked`) | 214 passed, 0 failed, 1 ignored |
| bbg (default / `--features serde`) | 88 / 93 passed, 0 failed |
| cybergraph `--all-features` | 103 passed, 0 failed |

## not done

- VEIL itself (above); WHIR-based zk (smaller openings) needs a zk WHIR in lens.
- The zk opening is unique-decoding Ligero: ~0.91 bits per query, so the
  opening is ~62 KB at 128 bits — at the proposal's 64 KB ceiling for one
  hash, larger than the succinct profile (~16 KB with WHIR).
- State statements in the zk profile: joy's private state queries use veil
  through the relation-level API (its tables are relation constants); a
  `StateStatement` zk variant does not exist.
- Prover constant time: not addressed (hemera's keyed XOF runs in constant
  time; the field arithmetic, NTTs and sumcheck do not).
- Verify ≤ 1 ms: 4.1 ms with a cached key at this fixture (opening 3.8 ms).
- joy `feat/zk-and-state-binding` builds against the stand's bbg only with
  joy `feat/no-legacy` merged (the base `feat/succinct-profile` still uses
  `zheng::LookOpening`, which bbg's consumer branch moved into bbg).
