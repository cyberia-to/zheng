//! Data parallelism over `std::thread::scope` for the one-relation
//! prover. Work is split into contiguous index ranges; results come back
//! in range order, so every reduction is the same field sum whatever the
//! thread count (field addition is exact).
//!
//! `ZHENG_THREADS` caps the worker count (phones: fewer, larger chunks);
//! unset, the available parallelism is used.

use std::sync::OnceLock;

/// Worker threads for the prover's data-parallel loops.
pub(crate) fn threads() -> usize {
    static N: OnceLock<usize> = OnceLock::new();
    *N.get_or_init(|| {
        let available = std::thread::available_parallelism().map_or(1, |n| n.get());
        std::env::var("ZHENG_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n >= 1)
            .map_or(available, |n| n.min(available.max(1)))
    })
}

/// `f` over `0..n` split into at most `threads()` contiguous ranges of at
/// least `min_chunk` items; the results in range order.
pub(crate) fn ranges<T: Send>(
    n: usize,
    min_chunk: usize,
    f: impl Fn(core::ops::Range<usize>) -> T + Sync,
) -> Vec<T> {
    let parts = threads().min(n / min_chunk.max(1)).max(1);
    if parts == 1 {
        return vec![f(0..n)];
    }
    let chunk = n.div_ceil(parts);
    let f = &f;
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..n)
            .step_by(chunk)
            .map(|lo| s.spawn(move || f(lo..(lo + chunk).min(n))))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("prover worker panicked"))
            .collect()
    })
}

/// Apply `f(offset, chunk)` to contiguous chunks of `v` in parallel.
pub(crate) fn chunks_mut<T: Send>(
    v: &mut [T],
    min_chunk: usize,
    f: impl Fn(usize, &mut [T]) + Sync,
) {
    let n = v.len();
    let parts = threads().min(n / min_chunk.max(1)).max(1);
    if parts == 1 {
        f(0, v);
        return;
    }
    let chunk = n.div_ceil(parts);
    let f = &f;
    std::thread::scope(|s| {
        for (i, c) in v.chunks_mut(chunk).enumerate() {
            s.spawn(move || f(i * chunk, c));
        }
    });
}
