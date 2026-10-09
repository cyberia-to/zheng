---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: zheng verifier, verification algorithm
---
# verifier

what a [[zheng]] verifier does, profile by profile. every proof arrives in the `ZHENGPF1` envelope; `Envelope::verify(state)` decodes it canonically and dispatches on the profile byte. the byte-level protocols are in [[execution]]; the bits each check carries are in the [[soundness]] ledger.

the old verifier this page used to describe — a 16-register trace, a recursive Brakedown opening claimed to need no hashing, a recursion tier counted in constraints — belongs to the legacy folded trace API (feature `legacy`, unsound, removed in phase 5). nothing below depends on it.

## common to every profile

the verifier never trusts the prover for the relation. from the statement it derives:

1. the subject shape (input length, Joy reverse-cons order, trailing zero);
2. the CCS, by recompiling the public program (`execution::relation`) — or takes it from a verifying key whose program key matches the statement's (`execution::vk`; keys are derived by the verifier only, never deserialised);
3. the pinned coordinates: `z[0] = 1`, the public inputs, the outputs and the cost wire, and for state statements every read's active flag, root limbs, namespace, key and value.

the prover can only influence the free (witness) positions. a pinned value is never read from the proof.

## profile 0 — public certificate v3

```
VERIFY_CERTIFICATE(statement S, certificate c) -> accept/reject:
  R  = compile(S.program, shape(S))            // or the verifying key's relation
  z  = [1] ‖ pinned(S) placed by the verifier
  fill the free positions from c, in index order; reject a trailing zero,
       a value ≥ p, or more values than free positions
  pad with zeros
  for every row of R: assert row(z) = 0        // exact, no challenge
  return accept
```

soundness error 0 for the compiled relation; size and verification are linear in the witness, and the witness is disclosed. measured: hash.tri 6,463 B envelope.

## profile 3 — state-public v3

as profile 0, preceded by authentication of the reads' `StateEvidence`: the 14 root leaves fold to the statement's `state_root` (`compress4`), every carried table matches its leaf, and every active read is answered from the authenticated tables before it is pinned. no caller authenticates anything on zheng's behalf.

## profile 1 — succinct

```
VERIFY_SUCCINCT(statement S, proof π) -> accept/reject:
  R, p = compile(S) relabelled to z' = (w ‖ p)       // p computed by the verifier
  admit(π.pcs_id, π.params, ℓ)                         // proven lens bits ≥ 128
  T = Transcript::new; absorb "zheng-succinct-v1", "zheng-vk" ‖ vk.digest ‖ S, pcs header, ℓ, m
  absorb π.root
  τ ← T (Fp3)
  outer sumcheck: log m rounds, degree d + 1, Fp3 challenges ρ_x
       (round polynomials without c_1; the verifier restores it from the running claim)
  absorb the t matrix evaluations; γ ← T
  inner sumcheck: ℓ + 1 rounds, degree 2 → point (r_0, r')
  lens transcript seeded by one squeeze of T
  assert claim = weight · ((1 − r_0)·v + r_0·p̃(r'))     // weight from R, p̃ from S
  assert PCS.verify(π.root, ℓ, r', v, π.opening)        // one WHIR opening
  return accept
```

shipped PCS: WHIR, rate 1/64, folding factor 4, 24 grinding bits; 128 proven bits, set by the PCS. measured (`audit/succinct-profile-2026-10.md`): hash.tri 16,148 B envelope, verify 7.96 ms; synthetic 2^20 relation 71,081 B, verify 270 ms. the verify goal (≤ 1 ms) is not met yet: hemera speed in the opening, the unstructured Spartan verifier and the relation recompile dominate; a cached verifying key removes the recompile.

## profile 2 — zk (veil)

as profile 1 on the masked relation (`veil::pad`), with Libra masks on both sumchecks and the opening replaced by one zero-knowledge linear test on a hiding RS tensor commitment (`veil::hiding`, masking rows, salted leaves). the verifier computes the pinned contribution `P` itself and checks one opened functional. 128.2 proven bits; honest-verifier statistical ZK, ZK in the ROM after Fiat–Shamir. measured (`audit/zk-profile-2026-10.md`): secret-preimage hash 63.9 KB, verify 10.0 ms (4.1 ms with a cached verifying key). scheme 1 (MPC-in-the-head, `ZHMITH01`) remains the linear-size fallback.

## profile 4 — machine proof (phase 3)

lands with accumulation (`accumulation.md`, `machine.md`, in progress in this release): the nox machine is one uniform step relation; the prover accumulates RS evaluation claims step by step (ARC/WARP-style), and the verifier checks the final accumulator with ONE WHIR opening. goal: ≤ 64 KB, verify ≤ 1 ms, constant in the number of steps; measured: the decider is 44–93 KB, but without recursion the whole proof grows with the steps — 83 KB (33 cycles), 146 KB (merkle-32), 384 KB (16,383 cycles, 3 segments), ~96 KB per 2^14-row segment (`audit/accumulation-2026-10.md`); decider verify 3.1–4.6 ms measured (hash.tri, merkle-32; whole machine proof 5–40 ms, linear in segments).

## profile 5 — recursive proof (IVC)

the nox run proven by incrementally verifiable computation (`recursion.md`): each 2^15-row step's circuit verifies the previous step, so the proof is the last step's proof, the state it started from, its accumulation step and one decider — constant in the number of steps. the verifier admits only the parameter sets of `envelope::recursive::ADMITTED` (WHIR rate 1/16 or 1/64, folding 4, 24 grinding bits, steps of 2^15 rows; every ledger row ≥ 128 bits), derives the circuit key of that set once per process (`ivc::key`, cached), prepares the statement side (`ivc::prepare`), verifies the step natively, checks the final state against this run (context, pre-commitment chain, step count, cyclic boundary), the three deferred claims, and the decider.

## recursion

a zheng verifier can be written as a nox program and proven (the Trident verifier). that is composition — proving a statement about proofs — and never the way proofs get small: size and constancy come from accumulation, not from re-proving verifiers.

## input format

```
ENVELOPE:
  magic    "ZHENGPF1"
  version  u16 LE (1)
  profile  u8  (0 public, 1 succinct, 2 zk, 3 state-public, 4 machine, 5 recursive)
  body     canonical: shortest LEB128, field values < p, flags 0|1,
           lengths bounded before allocation, no trailing bytes
```

see [[execution]] for each body, [[transcript]] for Fiat–Shamir, [[sumcheck]] for the core protocol, [[constraints]] for the CCS format, [[soundness]] for the bounds.
