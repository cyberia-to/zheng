# Private witness audit follow-up

Scope: the concrete findings in `audit/soft3-reaudit/proof-review.md`.

1. State the local timing/cache and incomplete memory-erasure boundaries in
   `specs/native-private-ccs.md`. Keep full local side-channel hardening open.
2. Evaluate every symbolic inverse through Goldilocks `inv()`. Its fixed
   exponent maps zero to zero, preserving the witness semantics while removing
   the measured skip for a secret-derived zero value.
3. Correct the public execution API comment to point at native private proving.
4. Run the existing native backend, relation, private state, and call tests plus
   the independent audit regression and timing diagnostic. Timing observations
   are audit evidence and never portable pass/fail thresholds.
5. Record the resulting evidence and remaining work. Commit after root review.

Implementation and focused validation complete; root review/commit pending.
The report records the baseline and the measured follow-up separately.

Remaining scope: activity-dependent witness/runtime branches, hidden table
indexing, field/runtime timing, caller-owned secret copies, ordinary private
witness vectors, and Hemera PRG state erasure. This change establishes neither
whole-engine constant time nor complete memory erasure.
