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
| tree-12 | 6 | PENDING | | | | |

† shared machine: two other agents' wrap chains ran during this prove and
the process swapped (swap up to 42 GB); #56 measured 43 s + 1,207 s for
hash.tri alone.

Cold verify = deriving the keys in the process: the IVC key (1.5–2 s)
and, for profile 6, the final key over the pinned roots; with an installed
bundle (`keys::install`, ~0.3 s: digest + rebuild) the joy CLI verifies in
0.13 s (profile 5, `joy/audit/wrapped-profile-2026-10.md`).

The envelope carries the statement, program tokens included: hash.tri's
is 249 B, tree-12's 73,766 B. The final proof is constant (62,685 B for
hash.tri), so a profile-6 envelope is ≤ 64 KB only for programs whose
tokens fit the remaining ~1.3 KB; binding the program by its digest
instead of its tokens is a statement-format decision left open.

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
