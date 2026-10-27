---
tags: computer science, cryptography
---
# zheng: polynomial proof system

one field: Goldilocks ([[nebu]]) for everything committed, its cubic extension Fp3 for every challenge and evaluation point.
one hash: [[hemera]] (Poseidon2 over Goldilocks) — Merkle trees and Fiat–Shamir, used as a random oracle. the code pins `cyber-hemera` 0.3 (0.3.1); the frozen material is hemera 0.4 (hemera#15), and zheng's move to it is the draft sweep zheng#69 / #73. every count and measurement in these specs is hemera 0.3.1.
one code: Reed–Solomon over Goldilocks, behind the [[lens]] PCS trait (WHIR shipped; TensorRs the bake-off loser, still decodable).
one IOP: [[SuperSpartan]] + [[sumcheck]] over CCS, challenges in Fp3; the nox machine relation is an AIR proved by a sumcheck zerocheck.
one wire format: the `ZHENGPF1` envelope (magic · version · profile · canonical body).

no FRI, no univariate quotient. soundness of every production component is recorded, with its assumption and bits, in the [[soundness]] ledger; its conjectured rows (relation compiler, hash, IVC and wrap composition) keep the repair's release gate open.

## profiles

every profile below exists in `rs/src/envelope` and verifies through `Envelope::verify`. figures are the audits' (Apple M4 Max, machine shared with other agents; sizes deterministic, times upper bounds); each names its source.

| envelope profile | name | what the verifier checks | size / verify (measured) |
|---|---|---|---|
| 0 | public certificate v3 | recompiles the CCS from the program, pins `z[0] = 1`, io and cycles, checks every row of the disclosed witness exactly; error 0 for the compiled relation | hash.tri 6,463 B (`audit/succinct-profile-2026-10.md`); linear, not succinct |
| 3 | state-public v3 | as profile 0, plus every read authenticated against the statement's own state root (`StateEvidence`) | linear |
| 1 | succinct | Spartan over Fp3, then one WHIR opening of the committed witness, rate 1/64; the default prover (`succinct::device_params`) folds by 4 up to 2^16 variables and 5 above and grinds 16 bits up to 2^17, 22 at 2^18, 24 beyond; ≥ 128 proven bits at every size up to the 2^20 relation cap | device parameters: hash.tri 16,756 B, verify < 10 ms; Merkle membership depth 16 59,722 B, depth 32 64,071 B (soft3 `audit/proof-latency-2026-10.md`). at `succinct::params_for` (folding 4, 24 grinding bits): hash.tri 16,148 B envelope, verify 7.96 ms; 2^20 relation 71,081 B, 270 ms (`audit/succinct-profile-2026-10.md`) |
| 2 | zk (scheme 2 veil; scheme 1 MPC-in-the-head fallback) | Libra-masked Spartan over Fp3 + one hiding RS tensor commitment opened by one zero-knowledge linear test; 128.2 proven bits | secret-preimage hash 63.9 KB, verify 10.0 ms (4.1 ms with a cached verifying key) (`audit/zk-profile-2026-10.md`); secret leaf at depth 12 ~295.6 KB (soft3 `audit/proof-latency-2026-10.md`) |
| 4 | machine proof (accumulation) | the nox machine as one step relation, its evaluation claims accumulated per step, decided by one WHIR opening | not constant: the decider is 44–93 KB, the whole proof 83 KB (33 cycles), 146 KB (merkle-32), 384 KB (16,383 cycles), ~96 KB per 2^14-row segment (`audit/accumulation-2026-10.md`) |
| 5 | recursive proof (IVC) | the last 2^15-row step natively (its circuit verified the step before), the final state against the run, three deferred claims, one WHIR decider; admitted parameter sets only (rate 1/16 or 1/64, 24 grinding bits) | constant in steps: hash.tri 407,947 B at rate 1/16 with 4-ary trees, decode + verify 9.5 ms (`audit/consistency-2026-10-27.md`); binary trees were 284,950 B (`audit/recursive-envelope-2026-10.md`) |
| 6 | wrapped proof | the profile-5 proof's final verifier proved by three wrap levels (`wrap::SHIPPED` = `4i:16,7i:22,9f:26`, the IVC at rate 1/8 with 16 grinding bits); the deferred nox-public claim against the statement, the public digest, one final-mode wrap proof natively; the program given out of band, checked against the statement's digest first | final proof ≤ 64,213 B over every transcript; hash.tri envelope 62,687 B, decode + verify 5.4 ms, prove 66.8 s on CPU with keys (`audit/consistency-2026-10-27.md`); add.tri 63,029 B, verify 1.9–2.2 ms with keys loaded; wrap chain 18.9 s on Metal, whole process 21.9 s, 11.2 GB (`audit/ivc-speed-2026-10.md`, `audit/ivc-speed-2-2026-10.md`); hash.tri envelope 62,940 B (`audit/proof-stack-review-2026-10.md`) |

the goal (owner, 2026-10-09; soft3 `proposals/proof-system-repair.md` §0): any nox computation → proof ≤ 64 KB, post-quantum (hash-only), verify ≤ 1 ms, constant in the number of steps. today profile 6 meets the size and the constancy and misses the verify time; profile 1 stays ≤ 64 KiB up to Merkle depth 32 (64,071 B) and misses the verify time; the second verifier in Trident and the phase-5 deletions are not done. figures re-measured on master at the 2026-10-27 promotion are in [the consistency receipt](../audit/consistency-2026-10-27.md).

## spec pages

Implementation reviews and validation evidence are indexed in
[audit](../audit/README.md).

- [[soundness]] — the soundness ledger: one row per production component
- [[execution]] — profiles 0–3, verifying keys, the `ZHENGPF1` envelope
- [[api]] — the public API: certify / prove / verify / envelope / verifying keys
- [[verifier]] — what each profile's verifier does
- [[lens]] — polynomial commitment (separate repo; `specs/whir.md`, `specs/tensor-rs.md`)
- [[sumcheck]] — the engine: O(N) prover reduces an exponential sum to one evaluation
- [[superspartan]] — CCS IOP via sumcheck: any-degree constraints, one PCS opening
- [[transcript]] — Fiat–Shamir via hemera, Fp3 challenges
- [[accumulation]] — hash-based accumulation of RS evaluation claims (ARC/WARP-style) and its decider (profile 4)
- [[machine]] — the nox machine as one uniform step relation (profiles 4–6)
- [[recursion]] — IVC over the nox machine and the wrap chain (profiles 5 and 6; `rs/src/recursion/`)
- [[native-private-ccs]] — the MPC-in-the-head private protocol (profile 2 scheme 1)
- [[ccs-execution-backends]] — how execution and state statements reach the CCS backends
- [[noun-cost-component]], [[disclosed-noun-memory]], [[disclosed-evaluation-dag]], [[disclosed-semantic-stream]] — the tagged relation's components
- [[constraints]] — CCS format, pattern table, state operations
- [[proof-types]] — the proof taxonomy of the stack
- [[tensor]] — tensor compression for O(√N) prover memory
- [[cli]] — the `zheng` binary (legacy feature only)
- [[phi-spmv]] — φ* SpMV circuit (legacy feature)
- [[accumulator]] — superseded: the legacy universal accumulator
- [[decider]] — superseded: the legacy decider, kept for its soundness residuals
- [proto](proto/README.md) — zheng's IOP as zippel protocols (executable checks, never a runtime)
- props: [dynamic noun memory](props/dynamic-noun-memory.md), [tagged symbolic relation](props/tagged-symbolic-relation.md) — draft proposals (not production contracts)

## architecture

```
zheng
├── execution (Rust: execution::*)
│   ├── relation compiler      nox program + subject shape → CCS
│   ├── certificate (v3)       profile 0 — exact row check
│   ├── state (v3)             profile 3 — reads authenticated under the state root
│   ├── succinct               profile 1 — Spartan/Fp3 + one lens opening
│   ├── veil                   profile 2 — masked Spartan + hiding RS tensor opening
│   ├── zk (MITH)              profile 2 scheme 1 — fallback, linear size
│   └── vk                     verifying keys, digest = hemera tree root of the relation
│
├── IOP layer
│   ├── SuperSpartan           CCS constraint system
│   └── sumcheck               generic over the challenge field (Goldilocks | Fp3)
│
├── lens layer (external repo)
│   ├── WHIR                   shipped (id 1)
│   └── TensorRs               bake-off loser (id 2), decodable until phase 5
│
├── hash layer
│   └── hemera                 Merkle trees + Fiat–Shamir (random oracle)
│
├── machine + air            the nox step relation (AIR, zerocheck by sumcheck)
├── accumulation             ARC/WARP-style: per step batch claims by sumcheck, commit one word,
│                            out-of-domain samples, a few queries; decider = one WHIR opening (profile 4)
├── recursion                IVC (profile 5) and the wrap chain (profile 6), field-native WHIR
│
└── legacy (feature `legacy`, off by default, unsound, removed in phase 5)
    └── folded trace API       commit/open/verify/fold/decide, universal CCS, phi
```

## the legacy fold

the 0.3 folded trace API (`commit`, `open`, `verify_eval`, `verify`, `fold`, `decide`, the universal CCS, phi) compiles only with the cargo feature `legacy`. it is unsound — the fold is never checked, the statement is unbound, the constant wire is free, and the Brakedown code distance is unproven ([[decider]] §soundness). it folded with a homomorphic-commitment protocol that hemera, a hash, cannot support; accumulation replaces it. constant size comes from IVC — the accumulation verifier inside the step relation (profiles 5 and 6); the whole verifier as a nox program (the Trident second verifier, not built) is for composition, never for size.

for intuition, motivation, and learning paths see [docs/explanation](../docs/explanation/). canonical design record: [[soft3/proposals/proof-system-repair|proof-system repair]].
