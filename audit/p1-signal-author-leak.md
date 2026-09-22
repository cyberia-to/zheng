---
tags: zheng, audit, privacy
---
# P1 signal privacy: the wire names the author in the clear

Status: gap analysis, 2026-09-21, re-aimed 2026-09-22 at the corrected P1.
Documentation only, no source changed. States precisely why the current
Signal spec and wire codec do not satisfy launch property 10 (P1), so the
property moves from "open, unexamined" to "open, precisely specified" per the
launch doctrine that a blocked code step still has a measurement to write.

## the requirement

`cyber/launch.md` (phase 1, core 6) corrected P1 on 2026-09-22: **the edge
is public, the author is private.** The network sees that particle p links
particle q, the axon weight, and the aggregates φ* is computed from; it does
not see which neuron signed, who holds the position, or who owns the energy.
The earlier wording — content visible only to participants, the network
sees a commitment — was withdrawn because hiding the edges themselves would
leave nothing for the collective φ* to run on. Property 10 in the registry
asks for a commitment plus a validity proof with bounded leakage, owned by
mudra and zheng. The registry's evidence line and the companion mudra audit
(mudra#3) still carry the pre-correction wording; this audit supersedes the
content-leak framing.

So the edges, weights and impulse on the wire today are not the gap. The
author is.

## what exists instead

[Signal](../../cybergraph/specs/signal.md) (`cybergraph@0eae7ae9`) specifies
the on-graph structure as

```
s = (ν, net, ℓ⃗, Δφ*, σ, h₀, h₁)
```

`specs/signal.md:11` types `ν` as `N`, the signing neuron, a plaintext field
of `s`. `σ` (`specs/signal.md:15,35-38`) is a zheng proof that covers link
validity, box movements and `Δφ*`; the spec never asks it to hide who signed.

[The durable signal codec](../../foculus/specs/signal-codec.md)
(`foculus@9e32aa68`) confirms this is not a modeling looseness. The payload
order is `neuron[32], network[32], prev[32], step(u64), height(u64), links,
delta_pi, box_moves, proof` (`specs/signal-codec.md:9-10`), and every link
carries the author again: `neuron/from/to/token[32], amount(u64),
valence(i8), height(u64)` (`specs/signal-codec.md:12`). In code:
`src/chain.rs:46` (`Signal.neuron`), `src/chain.rs:22`
(`CyberlinkRecord.neuron`), `src/signal_codec.rs:56,63` (both written to the
wire in the clear), `src/chain.rs:55-56` (`prev`, `step` — the hash chain of
one neuron's signals).

Authentication discloses the author by construction.
[NSIG1](../../mudra/specs/neuron-auth.md) is the implemented neuron
profile: the envelope is the compressed secp256k1 public key plus an
ADR-036 signature, and verification requires `claim::neuron_of(public)` to
equal the expected subject. A relayer that verifies a signal learns the key
and therefore the neuron.

So today every node that relays or stores a signal sees, per link, which
neuron asserted it, how much it staked, and — through `prev`/`step` — every
other signal that neuron ever sent. The one piece of the wire that already
hides ownership is the conviction box: `box_moves` carry a nullifier and a
commitment (`specs/signal-codec.md:13-14`), not an owner.

## what P1 legitimately leaves public, and the wire already gives

`from`, `to` (the edge), `token` and `amount` (the axon weight), `delta_pi`
(the impulse), `network`, `height`, `h₀`/`h₁`. None of these needs to move.
`valence(i8)` is on the wire too; that is property 29's finding (mudra#5),
not P1's, and is cross-referenced here only so the two audits do not
double-count it.

## why this is not a signal-codec bug

Dropping `neuron` from the codec breaks three things the network verifies
through it, and each needs a proof about a hidden author to replace it:

1. authorization — the signature proves the signer holds the energy the
   links spend (`(τ, a)` per link, backed by an unspent output). Without
   the key, σ must prove that *some* neuron with that energy authorized the
   spend: the nullifier/commitment model `box_moves` already use, extended
   to the link stake.
2. weight — tru's effective adjacency is
   `A_eff = Σ stake(ℓ) · κ(ν(ℓ)) · f(price(ℓ))`; the karma multiplier is a
   per-author attribute. A hidden author has to be *proven* to carry karma
   κ without being named — an attribute proof over witness data.
3. ordering — `prev`/`step` give one neuron one chain, which is replay
   protection and also perfect linkability: even with `ν` blanked, walking
   `prev` reassembles the author's whole history. Replay protection must
   move to nullifiers, or the chain must be hidden.

Each of the three is a fact about witness data (the signer, its stake, its
karma) that the verifier must accept without seeing the data. Zheng's
committed IOP stack — SuperSpartan + sumcheck + HyperNova over a Brakedown
lens (`specs/README.md:6-9`) — proves relations over inputs the verifier
sees; on `origin/master` a grep of `rs/src/` and `specs/` for hiding,
blinding or zero-knowledge witness handling returns nothing but one table
cell noting the isogeny lens is "shaped for" stealth and blind signatures
(`specs/README.md:69`), not an implemented capability. Closing property 10
therefore needs a hiding construction zheng does not have on `master` yet,
not a foculus-, cybergraph- or mudra-local fix — the same gap the companion
audit for property 12 (launch #12, still open) found blocking P3: a miner's
per-contributor marginal vector is proven by exact replay against a public
plaintext field, for the identical reason.

## what closing property 10 needs, concretely

1. An author commitment replacing `ν` and `link.neuron` on the wire, bound
   into the signal hash the way `net` already is. NSIG1 stays the local
   authority profile; the network-facing profile becomes the proof-native
   one `neuron-auth.md` reserves ("proof-native/hash-preimage profiles
   retain their separate specification").
2. σ extended (or a second proof) to certify, without opening the author:
   the spend is backed by energy the hidden signer holds, and the link
   weight the network applies uses that signer's κ — a hiding witness
   relation this repo's committed IOP stack does not define today.
3. Replay protection without a per-author chain: nullifiers over the spent
   boxes instead of `prev`/`step`, or a hidden chain — otherwise item 1 is
   undone by chain-walking.
4. A public leakage statement: P1 accepts `from`, `to`, `token`, `amount`,
   `delta_pi`, `network`, heights as visible; the bound to write is what
   the aggregates (φ*, per-cluster settlement) reveal about authorship — an
   anonymity-set argument over the cluster, in the shape
   [private-recovery.md](../../mudra/specs/private-recovery.md) already uses
   for payments.

None of the four is a local patch in isolation: 1 is a mudra interface, 2
is the commit-and-prove-without-opening primitive zheng's private
execution work needs for P3 as well, 3 is a foculus chain-model change, 4
is a spec decision.

## verified

Line citations checked directly against the committed revisions named
above (`cybergraph@0eae7ae9`, `foculus@9e32aa68`, mudra `specs/` at its
current HEAD, this repo's `origin/master`), read-only, no working-tree
changes made outside this repo. No source changed in this repo; the review
ran `cargo test --lib -p zheng` on `origin/master` with the sibling
manifests aligned and found the same 10 pre-existing failures with and
without this branch (133/134 passed), unrelated to this file.

## remains

- the author-commitment interface (item 1) against the particle definition
  decision open on `cyber/launch.md` (property 19);
- a hiding witness relation for authorization and karma (item 2) — no
  committed spec or code in this repo defines one yet;
- the foculus chain model without `prev`/`step` linkability (item 3);
- the leakage bound for what P1 accepts as public (item 4);
- refresh or retire the registry's row-10 evidence text and mudra#3, which
  still state the withdrawn "content commitment" requirement.

## risk

None — adds one markdown file, no behavior change. Revert is a clean single
commit revert.
