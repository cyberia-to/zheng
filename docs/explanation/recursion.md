# accumulation, IVC and wrap

how [[zheng]] turns a [[nox]] run of any length into one proof whose size does not depend on the length. three layers, each built and measured on the current code; the contracts are [[zheng/specs/accumulation|accumulation]], [[zheng/specs/machine|machine]] and [[zheng/specs/recursion|recursion]], the design record is [[soft3/proposals/proof-system-repair|proof-system repair]] §4.

two words the retired 0.3 pages used as one:

- accumulation — folding claims without verifying proofs. each step batches the evaluation claims of its words into one accumulator (one Merkle root and a fixed number of claims); one decider opens the last accumulator. the accumulator is constant, the proof is not: every step leaves spot-check openings that someone must check.
- recursion — a proof that verifies a proof. in zheng it is IVC: the verifier of step `i − 1` runs inside the relation of step `i`, so each step's openings are checked and consumed, and only the last step's travel.

the retired design — homomorphic folding of committed CCS instances over hemera, with an unchecked fold and a tiny fixed decider — never worked: folding by homomorphism needs a homomorphic commitment, and [[hemera]] is a hash. that code survives only behind the cargo feature `legacy` (unsound, off by default) until phase 5 deletes it.

## 1. the machine and accumulation (envelope profile 4)

the nox machine is one uniform row relation for every program (`rs/src/machine/`): 64-column rows, one row per continuation-machine step, 32-row hemera permutation blocks for noun digests, a write-once memory checked by logUp over Fp3. it is proved as an AIR by a sumcheck zerocheck (`rs/src/air/`) down to evaluation claims on the committed words. segments of `2^14` rows are accumulated hash-based (`rs/src/accumulate/`, WARP's claim-carrying structure with ARC-style out-of-domain samples):

```
for each segment i:
    claims_i  = evaluation claims of segment i's words (Reed–Solomon codewords)
    batch claims_i with the running accumulator by a sumcheck
    commit one combined word (hemera Merkle root)
    sample out-of-domain points, open a few query positions
    acc_i = (root, fixed number of claims)        size independent of i

decider: one WHIR opening of the last accumulator
```

measured (`audit/accumulation-2026-10.md`): the decider is 44–93 KB, but the whole proof grows with the run — 83 KB at 33 cycles, 146 KB for merkle-32, 384 KB for 16,383 cycles in 3 segments, about 96 KB per `2^14`-row segment. accumulation alone saves openings, not size.

## 2. IVC (envelope profile 5)

each `2^15`-row step proves its nox segment and runs, as the recursion circuit inside its own trace, the verifier of the step before: its sumchecks, its Merkle openings over a field-native hemera transcript and field-native WHIR, its accumulation checks. constraint evaluations are deferred as claims and checked once by the final verifier. a proof of any number of steps is the last step's proof, the state it started from and one decider.

measured (`audit/recursion-2026-10.md`, `audit/recursive-envelope-2026-10.md`): 282–285 KB from 33 cycles to 1.57M cycles — constant in the run — with decode and verify in 26.5 ms (hash.tri) and 32.1 ms (merkle-32). one IVC step proves in about 1.1 s on Metal (`audit/ivc-speed-2-2026-10.md`).

## 3. wrap (envelope profile 6)

the IVC proof's final verifier is itself proved by three wrap levels of the recursion circuit (`rs/src/recursion/wrap/`): two inner levels and one final level at a low rate, whose proof the verifier checks natively. the program is bound by its digest.

measured: the final proof is at most 64,213 B over every transcript (`wrap::tests::the_shipped_final_proof_is_at_most_64_kib_over_every_transcript`), 63,029 B for add.tri, verified in 1.9–2.2 ms with the statement prepared (`audit/ivc-speed-2026-10.md`); the wrap chain proves in 18.9 s on Metal, the whole profile-6 process in 21.9 s (`audit/ivc-speed-2-2026-10.md`). this is the profile that meets the ≤ 64 KB goal for any computation; it does not meet ≤ 1 ms verification, and it runs on aggregators, not on the user's device path.

## 4. what is proven and what is not

every per-step reduction — zerocheck, shift, memory, accumulation, decider, field-native WHIR — has a proven row in [[zheng/specs/soundness|the soundness ledger]], ≥ 128 bits with grinding. the composition of IVC and of the wrap levels is conjectured: knowledge soundness of a recursively composed Fiat–Shamir argument whose random oracle is evaluated inside the relation has no proof in the random-oracle model — the standard heuristic of every deployed recursive system. the recursion circuit's agreement with the native verifier is tested, not proven.

## 5. what it serves, and what is not built

| need | shape | status |
|---|---|---|
| a long nox computation | profile 6: IVC over the machine, then the wrap chain | built |
| [[fold mining]]: a cluster of tickets becomes one decider before minting | each ticket's claims and the cluster tree are accumulation steps (`accumulate::ccs` folds statements of one CCS); constant size needs IVC | accumulation built; settlement on it is foculus's, not done |
| a [[light client]] accepts a checkpoint over many epochs | accumulate per epoch with IVC, decide at the checkpoint | not built |
| one proof per block | the transactions' proofs aggregated into the block proof | in flight (zheng PR #70) |
| composition across domains or versions, `verify(verify(π))` | the whole zheng verifier as a nox program — the second verifier, in Trident, agreeing with Rust on every fixture | roadmap (phase 3 of the repair), not built |

see [[zheng/docs/explanation/CCS|CCS]] for the constraint language, [[zheng/docs/explanation/performance|performance]] for every profile's figures.
