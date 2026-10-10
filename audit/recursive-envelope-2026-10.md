---
tags: zheng, audit, recursion, envelope
crystal-type: audit
crystal-domain: crypto
---
# recursive envelope (profile 5) — 2026-10-09

Contract: `specs/api.md` § recursive (envelope profile 5),
`specs/verifier.md` § profile 5. Code: `rs/src/envelope/recursive.rs`.

Stand: zheng `feat/ivc-envelope` on `feat/ivc` 5650094 (PR #53), lens
`feat/accumulation` 3cf2aaa, hemera cf28a64. Machine: Apple M4 Max,
16 cores, rustc 1.95.0, `--release`, **shared with other agents (load
average 23–42 during the runs)**; times are single runs (verify: median
of 5) and upper bounds of a quiet machine. Sizes are deterministic.

## 1. rejection tests (`rs/tests/recursive_envelope.rs`, 296 s)

One IVC proof of hash.tri (input 7), shared by the tests:

- round trip: `from_bytes(to_bytes(e)) == e`, re-encoding is byte-identical,
  verifies; a changed input or cycle count is refused;
- every truncation of the 284,950-byte envelope is refused; a trailing
  byte after the envelope is `TrailingBytes`; inside the length prefix,
  98 truncated and one extended IVC proofs (prefix recomputed) are refused
  by the IVC wire;
- profile byte 0–4 on this body: not accepted; 6 and 0xff:
  `UnknownProfile`; format byte 0, 2, 0xff: `NonCanonical`;
- WHIR header with rate 1/2, 1/8, 1/32, 1/128 or 16 grinding bits, and IVC
  step sizes 0, 10, 14, 16, 20, 255: `NonCanonical` before any key is
  derived; a proof length beyond 1 MiB: `TooLarge`;
- bit flips: every bit of header, format, parameters, statement and length
  prefix, then every 1,031st bit of the proof: **4,164 flips, 2,916
  decoded, 0 accepted**.

The full-proof bit-flip scan of the IVC wire (2,275,056 flips, 0 accepted)
is in `recursion-2026-10.md` §4.

## 2. profiles on the same fixtures

Command: `cargo run --release -p zheng --example envelope_profiles --
hash.tri merkle-32`. Bytes = the whole envelope; verify = `from_bytes` +
`verify` (median of 5, after one warm-up call). Profile 1 at its shipped
parameters (rate 1/64); profile 4 at `params_for(20)` (rate 1/64, the
parameters joy uses); profile 5 at `recursive::params()` (rate 1/16).

| fixture | cycles | profile | envelope B | prove s | verify ms |
|---|---|---|---|---|---|
| hash.tri (7) | 61 | 1 succinct | 15,319 | 6.0 | 7.81 |
| hash.tri (7) | 61 | 4 machine | 97,212 | 38.0 | 6.00 |
| hash.tri (7) | 61 | 5 recursive | 284,950 | 47.7 | 26.50 |
| merkle-32 | 1,121 | 1 succinct | — (relation compiler: `Limit`) | — | — |
| merkle-32 | 1,121 | 4 machine | 222,704 | 133.4 | 13.00 |
| merkle-32 | 1,121 | 5 recursive | 285,303 | 80.5 | 32.12 |

The circuit key of the recursive profile is derived once per process and
cached (`ivc::key`): 223–315 ms cold (`ZHENG_DRY=1 ivc_bench`), so the
first verification in a fresh process costs that much more.

Profile 5 is constant in the run's length (282–285 KB from 33 cycles to
1.57M, `recursion-2026-10.md` §3); profile 4 grows with every segment.
Both miss the ≤ 64 KB / ≤ 1 ms goal; the route is the wrap step
(`recursion-2026-10.md` §6).
