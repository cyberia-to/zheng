# zheng roadmap

open proposals not yet in canonical spec. all other proposals are now in reference/ as canonical features.

## proposals

| proposal | status | target |
|----------|--------|--------|
| [[gpu-prover]] | draft | full pipeline in VRAM — 45-100x throughput on commodity GPU |
| [[ring-aware-fhe]] | **in reference** → [[ring-pcs]] | native TFHE bootstrapping — ring-structured CCS + dedicated jets |
| [[gravity-commitment]] | accepted | mass-weighted polynomial encoding — verification cost ∝ importance |
| [[recursive-brakedown]] | blocked | Merkle-free recursive lens opening — O(log N + λ) proof size, blocked on a soundness gap (`lens` issue #6) |

## lifecycle

| status | meaning |
|--------|---------|
| **in reference** | merged into canonical spec — this is the architecture |
| accepted | approved — ready to implement |
| draft | idea captured, open for discussion |
| blocked | analyzed, but hits a known unresolved defect — needs that fixed before it can move to draft/accepted |
