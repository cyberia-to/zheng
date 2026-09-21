---
tags: zheng, audit, privacy
---
# P1 signal privacy: the wire format is fully public today

Status: gap analysis, 2026-09-21. Documentation only, no source changed.
Precisely states why the current Signal spec and wire codec do not satisfy
launch property 10 (P1), so the property moves from "open, unexamined" to
"open, precisely specified" per the launch doctrine that a blocked code step
still has a measurement to write.

## the requirement

Launch's phase-1 privacy core states P1 as: "a signal's content is visible
to its participants; the network sees a commitment and a proof of validity"
(`cyber/launch.md` §6, core 6). Property 10 in the registry asks for this as
a commitment plus a validity proof with bounded leakage, owned by mudra and
zheng.

## what exists instead

[Signal](../../cybergraph/specs/signal.md) (`cybergraph@0eae7ae9`) specifies
the on-graph structure as

```
s = (ν, net, ℓ⃗, Δφ*, σ, h₀, h₁)
```

`specs/signal.md:13` types `ℓ⃗` as `L⁺`, the links themselves — not a
commitment to them. `σ` (`specs/signal.md:15,35-38`) is a zheng proof that
covers `ℓ⃗`'s validity, box movements and `Δφ*`, but the spec never asks the
proof to *hide* `ℓ⃗`; it coexists with `ℓ⃗` being a plaintext field of `s`.

[The durable signal codec](../../foculus/specs/signal-codec.md)
(`foculus@9e32aa68`) confirms this is not just a modeling looseness in the
spec prose: `signal_codec::encode_signal` puts the link contents on the wire
in the clear. `specs/signal-codec.md:12`: "Links contain
neuron/from/to/token[32], amount(u64), valence(i8), height(u64)." Every
field a link carries — who, what, how much — is encoded byte-for-byte, not
as a commitment opening. The proof that travels alongside
(`specs/signal-codec.md:15-16`) authenticates a Brakedown opening over
committed evaluations, which is a commitment to the *execution trace*, not a
substitute for hiding the link fields that are independently serialized in
plaintext right before it.

So today: every node that relays or stores a signal — not just its
participants — sees the full link vector. This is the opposite of P1's
"network sees a commitment," and it applies to the general signal path, not
only payments.

## why this is not a signal-codec bug

[mudra's private recovery](../../mudra/specs/private-recovery.md) already
solves an adjacent problem — hiding note values and recipient bindings for
payments — through encrypted notes, commitments and a proof relation scoped
to that transfer. It is not a general answer for P1: private recovery's
protected surface is a payment's value and recipient; P1's is a signal's
full content (arbitrary cyberlinks, not only token transfers), reaching a
general audience of relayers and stakers, not a single recipient doing
private discovery.

Making `ℓ⃗` a commitment and proving its opening only to participants,
while still proving `Δφ*` and box-movement validity to *everyone*, is a
private execution problem: the proof must attest facts about hidden witness
data (the links) without revealing that data. Zheng's committed IOP stack —
SuperSpartan + sumcheck + HyperNova over a Brakedown lens (`specs/README.md:6-9`)
— proves relations over inputs the verifier sees; a grep of this repo's
`rs/src/` and `specs/` for hiding, blinding or zero-knowledge witness
handling returns nothing but one table cell noting the isogeny lens is
"shaped for" stealth and blind signatures (`specs/README.md:69`), not an
implemented capability. Closing property 10 therefore needs a hiding
construction zheng does not have yet, not a foculus- or cybergraph-local
fix — the same underlying gap a companion audit (launch #12, still open)
found blocks property 12 (P3): a miner's per-contributor marginal vector is
proven by exact replay against a public plaintext field, for the identical
reason — nothing in the stack proves a fact about witness data without
also disclosing it.

## what closing property 10 needs, concretely

1. A commitment scheme for `ℓ⃗` (candidate: hemera over the lens commitment
   used elsewhere in the stack) replacing the plaintext link fields in
   `signal_codec::encode_signal`.
2. A participant-only delivery path for the opening — the actual link
   contents — so senders and named counterparties can read `ℓ⃗` while
   relayers cannot. `stealth` (`mudra/specs/stealth.md`) is the existing
   non-interactive key agreement primitive shaped for this; it has no
   implementation yet (no `stealth.rs` in `mudra/src`).
3. `σ` extended (or a second proof) to certify that the committed `ℓ⃗` is
   valid and consistent with the publicly proven `Δφ*` and box movements,
   without opening `ℓ⃗` to the verifier — a hiding witness relation this
   repo's committed IOP stack does not define today (see above).
4. A public leakage statement for what remains visible: `net`, `Δφ*`'s
   magnitude, `h₀`/`h₁`, and box-movement existence (if those stay public)
   all need their own bound, in the shape private-recovery.md already uses
   for payments.

None of these four is a zheng-, mudra- or foculus-local patch in isolation:
1 and 3 are the same commit-and-prove-without-opening primitive zheng's
private execution work already needs for other properties; 2 reuses an
unimplemented mudra primitive; 4 is a spec decision, not a code change.

## verified

Line citations checked directly against the committed HEAD of each sibling
repo at the revisions named above, read-only, no working-tree changes made
outside this repo. No source changed in this repo; `cargo check --tests` and
`cargo test` were not required for a documentation-only change and were not
run.

## remains

- freeze the commitment scheme for `ℓ⃗` (item 1) against the particle
  definition decision already open on `cyber/launch.md` (property 19);
- implement `mudra::stealth` (currently spec-only) or select another
  participant-delivery primitive (item 2);
- extend zheng's IOP with a hiding construction that can prove validity
  over a hidden `ℓ⃗` (item 3) — no committed spec or code in this repo
  defines one yet;
- write the leakage bound for what P1 accepts as public (item 4).

## risk

None — adds one markdown file, no behavior change. Revert is a clean single
commit revert.
