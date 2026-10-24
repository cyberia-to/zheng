---
tags: computer science, cryptography, zheng, tooling
crystal-type: reference
crystal-domain: computer science
alias: zippel
---
# zippel — what it is, what it gives zheng

[eniac/zippel](https://github.com/eniac/zippel) (UPenn, S&P 2027, MIT, nightly Rust, ~82 K lines, active) is a *choreographic* language for proof systems: one `.zippel` file describes prover and verifier together, the way a paper's pseudocode does. The compiler lowers it to a DAG (Graph IR), **projects** the DAG into a prover subgraph and a verifier subgraph by visibility (what the verifier can reach from instance values, challenges and prover messages), derives the Fiat–Shamir transcript from the projection (every `<-` message is absorbed, every `challenge` squeezed, instance bound into the domain separator — weak Fiat–Shamir is impossible by construction), and runs the two subgraphs on a work-stealing scheduler over arkworks. Independently it runs two **static analyses** on the unprojected graph: completeness and $(\ell_1,\dots,\ell_\mu)$-special soundness, by encoding node semantics as polynomial ideals and checking ideal membership with Gröbner bases, bounded to concrete sizes. 35 protocols ship as examples (Schnorr … KZG, Bulletproofs, Hyrax, Spartan, HyperPlonk, Groth16, Dory, sumcheck, zerocheck); two thirds were written by AI agents with the type system and the analyses as the oracle.

## what it does not do

- no hash-based proof systems, no codes, no lattices, no GPU: the backends are curves and pairings (BLS12-381, BN254, curve25519, secp256k1). Brakedown, WHIR, Merkle paths and hemera are outside it.
- no Goldilocks field: arkworks can host a 64-bit prime (`MontBackend`, one limb), and zippel's `nothing/` backend already serves the analysis path without a group — so an analysis-only Goldilocks configuration is a small addition, not a port.
- the analyses prove completeness and special soundness only — no knowledge soundness beyond that, no zero-knowledge analysis; they can time out, which says nothing; sizes are bounded (the paper's 94 % pass in under a minute at small sizes).
- recursion is primitive recursion by size overloading (Spartan's sumcheck is written that way); no control flow.
- research prototype, unaudited, never a runtime dependency of anything of value.

## what zheng takes from it

1. **The transcript is derived, not maintained.** zheng's [[transcript]] page lists domain separators and the "~3 hemera calls" plus an algebraic Fiat–Shamir path by hand. That is the exact class of bug zippel removes by construction. Lesson: the protocol description is the source, the absorb/squeeze order is generated from it, the spec page documents the generated order.
2. **An oracle for agent-written cryptography.** Our protocols are written and rewritten by agents. zippel's completeness and special-soundness checks are the first fully automated ground truth for "does this IOP prove what it says" — the missing gate between a passing test and a sound protocol.
3. **Visibility types.** `witness` / `instance` / `extra`, checked at compile time, so a verifier cannot read a prover-only value. zheng's API separates prover and verifier by convention.

## how it embeds — as a checker, never as a runtime

- `zheng/specs/proto/*.zippel`: executable specs beside the markdown — [[sumcheck]], [[superspartan]] (outer and inner sumcheck over CCS), the HyperNova fold step and the [[decider]]'s algebraic part. The PCS is an oracle in these files (an `instance` evaluation), which is how IOPs are analysed anyway; the lens's own soundness stays with the lens.
- a CI job on zippel's pinned nightly toolchain, separate from the stable workspace: `cargo zcheck` on every file, then completeness and special soundness at small sizes. The release-train gate for zheng includes it.
- a Goldilocks analysis backend contributed upstream, so sized-type checks (degree against field size) run in our field.
- diff the derived transcript against [[transcript]]: every disagreement is either a spec bug or a doc bug.

Not: replacing zheng's prover or verifier with zippel's runtime (arkworks, big fields, CPU only, no hash-based commitments), and not a dependency in any soft3 crate.

## first experiment

Write [[sumcheck]] and the SuperSpartan outer sumcheck as `.zippel` from zippel's `mle_sumcheck` and `spartan` examples, run the two analyses at `NUM_VARS = 3..4`, and compare the absorb/squeeze order with the transcript page. One day. If the analyses pass and the orders disagree, the page is wrong; if they fail, the protocol is.
