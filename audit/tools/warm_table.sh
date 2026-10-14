#!/bin/bash
# warm_table.sh <fixture…> — in-process proving with the proving key held
# (`fast_path` with FAST_KEY=1, median of FAST_REPS, default 5), per
# backend, with the process's peak RSS. The held-key proof is asserted
# byte-equal to the cold one on every run.
#
#   FAST_PATH  the example binary: cargo build --release -p zheng --example
#              fast_path, then $CARGO_TARGET_DIR/release/examples/fast_path
#   BACKENDS   default "metal cpu webgpu"
X=${FAST_PATH:?FAST_PATH: the fast_path example binary}
for f in "$@"; do
  for b in ${BACKENDS:-metal cpu webgpu}; do
    out=$( { FAST_KEY=1 FAST_REPS=${FAST_REPS:-5} ZHENG_BACKEND=$b /usr/bin/time -l "$X" "$f"; } 2>&1 )
    row=$(echo "$out" | grep "^| $f ")
    warm=$(echo "$out" | sed -nE 's/.*key ([0-9.]+) ms once; warm prove ([0-9.]+) ms.*/key \1 warm \2/p')
    rss=$(echo "$out" | awk '/maximum resident/{printf "%.0f", $1/1048576}')
    echo "$f $b | $warm | rss ${rss}MB | $row"
  done
done
