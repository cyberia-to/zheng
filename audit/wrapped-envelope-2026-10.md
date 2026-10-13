# wrapped envelope (profile 6) and key layouts — 2026-10-10

Contract: `specs/api.md` § wrapped, § key bundles; `specs/verifier.md`
§ profile 6; `specs/recursion.md` § envelope, § key layouts.

Stand: zheng `feat/wrap-envelope` (on `feat/wrap` 606cda1, #54 merged in),
lens `feat/field-native-whir` c91f55a. Apple M4 Max (16 cores, 48 GB),
`--release`. **The machine is shared**: other agents ran wrap chains
(`wrap_bench`, `wrap_flip`) at the same time as some of the runs below;
those runs are marked, and their times are upper bounds. Sizes are
deterministic.

## keys

`examples/wrap_keys` (fresh process each):

| what | time | memory | bytes |
|---|---|---|---|
| IVC key (rate 1/16, 2^15 rows), derived | 1.5–1.7 s | — | layout 1,266,568 |
| IVC key, rebuilt from its layout | 13–26 ms | — | |
| wrap chain, prover derivation (commits both inner keys) | 178 s (182 s process) | max RSS 30.9 GB, peak footprint 45.2 GB | |
| final key, verifier derivation over the pinned roots (IVC key cached) | 0.5–2.0 s | — | layout 1,316,245 |
| final key, rebuilt from its layout (threaded wiring) | 145 ms (996 ms with the serial wiring) | — | |
| hemera digest of a bundle | 74 ms (profile 5), 149–152 ms (profile 6) | — | 1,266,580 / 2,582,828 |

Pins: `keys::RECURSIVE_DIGEST` 11e158ef…, `keys::WRAPPED_DIGEST`
81a9a4e1…, `wrapped::INNER_ROOTS` from the prover's derivation
(`tests/keys.rs`; the root check against a full derivation is the
ignored `the_pinned_inner_roots_are_the_derived_ones`).

## profiles 1 / 5 / 6

`examples/envelope_profiles`: prove = the whole process
(`/usr/bin/time -l`); cold verify = decode + verify in a fresh process
(`ZHENG_VERIFY=<file>`, keys derived), warm = median of 5 more in that
process.

| fixture | profile | envelope B | prove | max RSS (prove) | verify cold | verify warm |
|---|---|---|---|---|---|---|
| hash.tri (61 cycles) | 1 | 15,319 | 6.5 s | 8.9 MB | 8.0 ms | 7.4 ms |
| hash.tri | 5 | 323,382 | 44.2 s | 4.13 GB | 1,715–2,078 ms | 24.7–30.0 ms |
| hash.tri | 6 | **62,962** | 2,511 s † | 29.2 GB (peak footprint 60.0 GB) | 4,216–4,613 ms | 20.9–24.1 ms (10.3 ms in the prover's process) |
| tree-12 (16,383 cycles, 2 steps) | 1 | — (relation compiler: size/depth limit) | | | | |
| tree-12 | 5 | 396,931 | 103.2 s | 7.47 GB | 3,302–3,455 ms | 71–154 ms |
| tree-12 | 6 | 136,671 (final proof 62,877 B; statement 73,766 B) | 1,672 s ‡ | 27.1 GB (peak footprint 60.3 GB) | 1,928–1,942 ms | 28.9–29.1 ms |

† shared machine: two other agents' wrap chains ran during this prove and
the process swapped (swap up to 42 GB); #56 measured 43 s + 1,207 s for
hash.tri alone. ‡ alone on the machine for most of the run (#56: 47 s +
1,235 s). A first tree-12 run, during other agents' chains, died after
863 s with a 57.8 GB footprint and no output; the rerun above passed.

Cold verify = deriving the keys in the process: the IVC key (1.5–2 s)
and, for profile 6, the final key over the pinned roots; with an installed
bundle (`keys::install`, ~0.3 s: digest + rebuild) the joy CLI verifies in
0.13 s (profile 5, `joy/audit/wrapped-profile-2026-10.md`).

The envelope carried the statement, program tokens included: hash.tri's
226 B, tree-12's 73,743 B — tree-12's profile-6 envelope was 136,671 B
around a 62,877 B final proof.

### the program bound by digest (2026-10-13)

Profiles 4–6 now carry the program's hemera digest (32 B) in place of its
tokens (`specs/api.md` § the program of profiles 4–6). The final proof's
wire is unchanged (its shape depends on the chain and the step count
only), so the envelope sizes follow exactly from the measured proofs:
`11 (header) + 1 (format) + 36 (chain) + statement + 3 (length) + proof`,
which reproduces the two measured envelopes above byte for byte
(62,962 and 136,671).

| fixture | statement before → after | final proof (measured) | profile-6 envelope after |
|---|---|---|---|
| hash.tri | 226 → 87 B | 62,685 B | **62,823 B** (computed) |
| tree-12 (2 steps) | 73,743 → 48 B | 62,877 B | **62,976 B** (computed) |

Statement sizes: `machine::execute_exact` on each fixture, encoded as the
envelope encodes them. The re-prove of tree-12 under the new transcript
(`MachineStatement::bytes` v2) was killed by the OS after 702 s (max RSS
36.0 GB, footprint 49.9 GB; 15 GB of disk left for swap, other agents'
chains running), so these two sizes are computed, not read off a fresh
envelope; the transcript change alters proof bytes, not sizes.

## rejection tests

`tests/wrapped_envelope.rs`: a chain outside the admitted one (every
chain byte changed, format byte, step size), a length beyond the bound
and an empty proof are refused with no key built (default run). With an
envelope (`--ignored`): round trip, ≤ 64 KB, statement binding (input,
cycles, budget, output), every truncation of the envelope and of the
proof inside its length prefix, a trailing byte, wrong profile and format
bytes, a final proof of another step size, a bit-flip sample.
`tests/keys.rs`: pinned digests equal the derived keys', layouts rebuild
the same keys (wiring included), tampered/truncated/relabelled bundles
are refused.

## follow-up: #58

zheng #58 (`feat/wrap-fastverify`, on `feat/wrap`) changes the wrap
chain's levels and proof shapes; proofs of #56 do not verify under #58's
keys. When #58 merges, profile 6 must follow it: `wrapped::chain()` (the
allow-list), `wrapped::INNER_ROOTS`, `keys::WRAPPED_DIGEST` re-derived
(`examples/wrap_keys`), `WRAPPED_FORMAT` bumped, and these numbers
re-measured.
