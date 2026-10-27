---
tags: zheng, audit, succinct, veil, latency, merkle, jets
crystal-type: report
crystal-domain: crypto
date: 2026-10-14
---
# fast path 2 — the last ≤ 1 s gaps, 2026-10-14

note (2026-10-27): the `.stands/` checkouts named below were removed in the cleanup of 2026-10-16; the revisions they held are named here, the directories are gone.

Follow-up of soft3 `audit/proof-latency-2026-10.md` (zheng#64, lens#25).
That audit left three gaps on the user-device path: (a) Merkle membership
at depth 32 (1.13 s cold / 0.61 s warm on Metal, 64,071 B, 22 grinding
bits); (b) veil secret-leaf membership at depth 16/32 (0.94 / 2.0 s,
295–545 KB); (c) ~0.7 s of Metal shader compilation in the first process.
A later ask from the product side (mudra#22, P1 authorship on veil: depth
20 = 965 ms, depth 24–32 = 1.3–1.4 s) added held proving keys for veil and
for caller-built profile-1 relations, public readers of proof bytes, and a
seeded test hook.

Stand `~/cyber/.stands/F2`: zheng `feat/fast-path-2` (off `release/0.4`
aa54bdd), lens `feat/fast-path-2` (off `release/0.2` ff2c160), joy
`feat/fast-path-2` (off `release/0.4`), nox/trident `release/0.4`, hemera,
strata, honeycrisp `main`, bbg 48153b2; mudra PR #22 head a6dd4ba for the
P1 numbers. Apple M4 Max, macOS 26.4, `--release`. **The machine was
shared with other agents; load average 24–50 during the tables below** (it
reached 130 during the day). Bytes and SHA-1s are deterministic; times are
medians of 3 (cold) or 5 (warm).

## 1. (a) the hemera node jet — one permutation per Merkle level

**Why a level cost ~5,000 wires.** nox pattern 15 hashes nouns
structurally: a digest noun `[[a b] [c d]]` costs four atom hashes (each a
64-bit decomposition and two permutations) and three pair nodes, so
`[15 [cur sib]]` is 24 permutations and 512 bit wires — and the direction
mux puts both children in the circuit. No cheaper circuit computes that
function: it is what nox defines.

**What changed.** `zheng::execution::node` defines a second function, the
one hemera's Merkle trees (and bbg's paths) actually use: `hash_node(L, R)`
= `permute(L ‖ R ‖ 0 ‖ flags ‖ 0⁶)[0..4]` over 4-limb digests (`flags` 2
interior, 3 root). Its semantics are a pure Layer-1 nox formula,
`node::formula()` (2,235 nodes, nests 39 deep): the Poseidon2 permutation
in nox arithmetic, its partial-round inverse `x^(p−2)` by square-and-
multiply over the exponent's runs of equal bits — every branch tests a
constant of the formula, so its cost is `node::COST` = 39,818 cycles for
every input, and `0 ↦ 0` as in hemera. Three consumers:

- the relation compiler (`relation_node.rs`) meets a formula equal to it
  token for token and emits one permutation gadget (the existing
  `hash_permute`) over the eight limbs and the flags, charging `COST`; any
  other subject shape fails closed, as nox does;
- nox's jet registry (`node::jet::register`) for native runs: admission
  declines off-shape subjects and budgets below the cost, so pure dispatch
  keeps nox's exact errors and halts;
- joy's independent native check (joy `feat/fast-path-2`): reduces with the
  registry and counts cycles as the budget spent (a jet records one trace
  row for its whole cost). Without it the native check of a depth-32 path
  ran ~1.3M reductions and 8–12 GB.

The fixture `node_merkle_program(d)` (tests/common) is the same path as
`merkle_program(d)` — leaf `hash(x)`, the same siblings and directions —
through the node: the node formula and both level formulas ride in the
subject once and every level is a 9-token step, so depth 32 fits the
4,096-node program cap.

### before → after, Metal

`joy prove` in a fresh process (wall s; prove ms as joy reports), OS shader
cache and lens archive warm; warm = in-process with a held key
(`fast_path`, `FAST_KEY=1`). "before" is the structural fixture on the same
binaries in the same session (it matches the 2026-10-14 audit within load).

| statement | relation (vars / rows) | cold | warm | bytes | grinding | verify |
|---|---|---|---|---|---|---|
| merkle-12, structural (before) | 2^16 / 2^17 | 0.36 s (audit) | 162 ms (audit) | 50,818 | 16 | 120 ms |
| merkle-32, structural (before) | 2^18 / 2^18 | 991 ms · 1.02 s | 535 ms | 63,594 | 22 | 320 ms |
| node-merkle-12 | 2^13 / 2^13 | 90 ms · 0.12 s | 41 ms | 41,803 | 16 | 19 ms |
| node-merkle-16 | 2^13 / 2^13 | 96 ms · 0.12 s | 43 ms | 42,914 | 16 | 21 ms |
| node-merkle-32 | 2^14 / 2^14 | 128 ms · **0.15 s** | 62 ms | 46,719 | 16 | 31 ms |

CPU / WebGPU cold, node-merkle-32: 0.20 / 0.23 s; peak RSS 110–181 MB
(structural depth 32: 1.0–2.2 GB). Envelopes are SHA-1 equal across the
three backends (`e13a8d01` at depth 32). The envelope includes the program
(~5 KB for the node formula). Ledger: `device_params` at 2^13 / 2^14 is 16
grinding bits, 128.08 proven bits (112.08 without grinding) — the 22-bit
grinding of 2^18 is gone. `joy verify` 0.04 s (structural 0.33 s).

**Target met**: depth 32 ≤ 0.5 s cold on Metal — 0.15 s wall, 0.20 s CPU.

**What it is not.** The node is a different hash from pattern 15: a
program chooses its tree. Product statements built on `H([L R])` =
pattern 15 (mudra#22's P1 authority set is) keep the structural cost until
their spec moves the tree to `hemera::merkle`'s node; bbg's paths already
are `hash_node` trees. Trident/joy have no surface syntax for the jet yet:
a program includes `node::formula()` as data (as the fixture does).

## 2. (b) veil — counter-mode coins and a held key

Details, PRF bound, HVZK argument, constant-time discussion and the
independent review: [veil-coins-2026-10.md](veil-coins-2026-10.md). In
short: the prover's coins are `π_ct(K ‖ label ‖ block ‖ 0⁹ ‖ TAG)[0..8]`
with `K = derive_key(seed)`, the seed from OS entropy, one label per
consumer; fills run in parallel and equal the sequential fill; the codeword
rows encode one per thread. The HVZK simulator is unchanged; the distance
grows by the PRF advantage (≈ 2^-175 at 2^80 offline queries). Bit-flip
scan of a veil envelope: 507,584 flips, 0 accepted.

`veil::ProvingKey` holds the compiled relation, its verifying key, the
masked relation, its layout and the relabelled masked relation; a keyed
proof equals `prove_bound`'s under equal coins (test).

| statement (Metal, in-process) | before (audit) | coins only | coins + held key | bytes |
|---|---|---|---|---|
| veil-merkle-12 | 690 ms (cold) | 388 ms | 244 ms | ~293 KB |
| veil-merkle-16 | 938 ms | 523 ms | 343 ms | ~419 KB |
| veil-merkle-32 | 2,024 ms | 977 ms | 638 ms | ~546 KB |
| veil-node-merkle-12 | — | 83 ms | 64 ms | ~130 KB |
| veil-node-merkle-32 | — | 134 ms | 96 ms | ~165 KB |

`joy prove --secret` cold, Metal: veil-merkle-12 0.41 s (was 0.71 s),
veil-node-merkle-32 0.18 s (181 KB). Verify: 40 ms at node depth 32, 374 ms
structural depth 32.

**mudra#22 P1 authorship** (`examples/p1_bench`, mudra unchanged except
where stated, P1_REPS = 5, load 27–28):

| depth | PR #22 as measured there | on these branches | + held veil key (3-line mudra change) | bytes |
|---|---|---|---|---|
| 20 | 965 ms Metal / 1,004 CPU | 488 ms Metal | **255 ms** Metal / 306 CPU | 293 KB |
| 32 | 1,342 ms / 1,414 | 748 ms | **396 ms** / 477 CPU | 419 KB |

The held-key change for mudra (not committed — mudra belongs to the
product-wiring work): `Key` holds `veil::ProvingKey::new(&program, 12)`
and `prove` calls `veil::prove_with_key`; mudra's 11 authorship tests pass
with it. Its `vk` can then come from `pk.verifying_key()`.

**Proof size.** ≤ 64 KB is not reached. Measured levers
([veil-coins-2026-10.md](veil-coins-2026-10.md) §7): rate/grinding
choices buy ≤ 5.4 % (the Ligero-style opening is in unique decoding, ≥ 112
queries at any rate); dropping `m_b` 0.2 %; Libra masks no measurable
effect. The large levers are new soundness work, estimated only: shorter
row padding (−13…19 %), a list-decoding analysis of the zk linear test (~47
queries instead of 123), or a hiding WHIR (~95–160 KB at structural depth
32, against the non-hiding 63.6 KB). The relation size is what moves bytes
today: the node tree takes depth 32 from 546 KB to 165 KB.

## 3. (c) Metal shader start-up

lens `gpu/src/metal_cache.rs` (+ `metal_objc.rs`): the twelve pipelines
are created concurrently and cached in an `MTLBinaryArchive`
(`$LENS_SHADER_CACHE`, default `~/Library/Caches/cyber-lens`), keyed by
source, device, OS and crate version, loaded with
`FailOnBinaryArchiveMiss`; any failure falls back to compiling, written
atomically; a build machine with `xcrun metal` embeds a metallib (this Mac
has no offline Metal compiler, so that path is built but unexercised).
Measured by lens (`audit/metal-shader-cache-2026-10.md`, load 37–48,
cold OS cache via fresh app bundles): `Metal::new` 4.0–4.2 s sequential →
1.9–2.3 s concurrent → **0.15 s** with the archive present; warm OS cache
27–33 ms. Here (joy, warm OS cache, empty archive directory): first process
0.31 s, later 0.17 s. The first process after a kernel change still pays
the concurrent compile (no archive can exist for an unseen source); the
WebGPU pipeline cache is Vulkan-only in wgpu 28 and was not used.

## 4. product-side asks (mudra#22)

- held proving key for veil: `veil::ProvingKey`, `prove_with_key`,
  `prove_bound_with_key` (§2);
- smaller veil proofs: §2 — numbers and levers, no format change;
- per-component zk tests downstream: `veil::revealed(statement, proof)` /
  `revealed_relation` return every revealed value by category (zheng's own
  `zk_tests` now use it); feature `test-hooks` adds
  `veil::testing::prove_with_key_seeded` for reproducible tests (a fixed
  seed fixes every mask — tests only);
- profile 1: `succinct::RelationKey` + `prove_relation_with_key` for a
  relation the caller built (same bytes as `prove_relation`), and
  `envelope::succinct_proof_from_bytes`, the decoder of
  `succinct_proof_bytes` (every byte consumed).

## 5. self-review

Soundness of (a):

- *Equivalence.* The gadget and the formula are the same function: the
  gadget is `hash_permute` (checked against hemera since #64) on the state
  the formula builds; the formula reduces under native nox (pure L1,
  `nox::reduce`) to `hemera::tree::hash_node` for both flags on random,
  zero and `p − 1` limbs, with cost `COST` every time
  (`node::tests`). Relation = native nox = hemera on random paths whose
  leaf, siblings and directions are inputs, output and cycles, depths 1, 2,
  3, 5; zheng's machine agrees (`tests/node_merkle.rs`).
- *Recognition.* Exact token equality with `node::formula()`; a near-copy
  compiles pattern by pattern. The verifier recompiles with the same rule.
- *Shape.* `[[L R] flags]` with atom limbs and an atom flag, else the
  compiler fails closed — nox fails on the same subjects (tested).
- *Depth.* nox refuses past 1,000 nested reductions, the compiler past
  128; the node reduces natively under 640 nested levels (tested), so the
  relation never accepts a program nox's depth limit rejects.
- *Attacks.* Every tampered sibling limb and every flipped direction at
  depth 4 misses the root, natively and in the relation; an interior flag
  at the root misses it; a proof of a tampered path cannot claim the honest
  root (verification fails); bit-flip scan of a depth-4 node-merkle
  envelope (29,687 B): 237,496 flips, 0 accepted.
- *Jet in nox runs.* Jetted = pure on random subjects, flags 0 and `p − 1`,
  a composed program and off-shape subjects (equal outcomes, including the
  error); the jet provably fires (a 4,096-slot arena only suffices with
  it).
- *Ledger.* New row "relation compiler — hemera node jet" in
  `specs/soundness.md` (no error term; inherits the compiler row);
  `specs/execution.md` documents the jet and corrects the relation cap
  (2^20). Grinding at the new sizes: 16 bits, 128.08 proven.

(b) was implemented separately and reviewed independently
([veil-coins-2026-10.md](veil-coins-2026-10.md) § independent review); the
held key is a pure refactor of the prover's setup (byte-equal under equal
coins). Not constant time downstream of the coins (encoding, lens Merkle
leaves) — unchanged and stated.

Suites on the merged branch: zheng 394 passed, 0 failed, 19 ignored (with
`test-hooks`); joy 219 passed against the branches, plus its new node-jet integration test; lens gpu differential
15 and shader-cache 4 (`LENS_GPU_REQUIRE=metal,webgpu`), rspcs 43.

## 6. commands

Fixtures: `FAST_DUMP=<dir> fast_path <name>…` writes `<name>.nox` with
`.inputs` (profile 1) or `.secret` (veil). Tables:
`JOY=<joy> FIXTURES=<dir> audit/tools/joy_table.sh <names>` (cold, per
backend) and `FAST_PATH=<fast_path> audit/tools/warm_table.sh <names>`
(held key); `audit/tools/tree.py` reads `sample` call trees.
