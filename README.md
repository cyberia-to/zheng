the proof system for [[cyber]]. implements the Whirlaway architecture: [[SuperSpartan]] IOP + [[WHIR]] PCS + [[sumcheck]] protocol. zero trusted setup. post-quantum. sub-millisecond verification.

zheng (証 — proof/evidence in Japanese) provides the cryptographic machinery that turns [[nox]] execution traces into compact, verifiable proofs. one commitment, one opening, one proof.

```
COMPONENT         │ ROLE                          │ INSTANCE
──────────────────┼───────────────────────────────┼─────────────────────
hash              │ Fiat-Shamir, Merkle trees     │ hemera 
field             │ arithmetic substrate          │ nebu
VM                │ execution trace generation    │ nox
IOP               │ constraint verification        │ superspartan
core protocol     │ exponential sum → log rounds   │ sumcheck
PCS               │ polynomial commitment          │ whir
```

## dependency graph

```
nebu (field)
  ↓
hemera (hash)
  ↓
zheng (proofs) ← this repo
  ↓
bbg (state)
```

see [[stark]] for the general theory, [[cyber/proofs]] for the full proof taxonomy
