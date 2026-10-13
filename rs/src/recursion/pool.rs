//! A small persistent worker pool for the native verifier's parallel
//! passes. A verification makes a handful of short parallel passes
//! (a few hundred microseconds each); spawning threads per pass costs the
//! calling thread more than the pass saves. Workers start once, sleep on a
//! condition variable, and take task indices from the posted job; the
//! caller takes tasks too and returns when every task has run.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

/// A posted job: `f(i)` for every `i < n`.
struct Job {
    /// The caller's closure, its lifetime erased; valid until `done == n`
    /// (the caller waits for that before returning).
    f: *const (dyn Fn(usize) + Sync),
    n: usize,
    next: AtomicUsize,
    done: AtomicUsize,
    panicked: AtomicBool,
    /// Signalled when the last task finishes.
    fin: (Mutex<()>, Condvar),
}

// SAFETY: `f` points to a `Sync` closure that outlives every use (see
// `Job::f`); the other fields are atomics.
unsafe impl Send for Job {}
unsafe impl Sync for Job {}

impl Job {
    /// Run tasks until none is left.
    fn work(&self) {
        loop {
            let i = self.next.fetch_add(1, Ordering::Relaxed);
            if i >= self.n {
                return;
            }
            // SAFETY: `i < n`, so the caller is still waiting for this
            // task: the closure is alive.
            let f = unsafe { &*self.f };
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(i))).is_err() {
                self.panicked.store(true, Ordering::Relaxed);
            }
            if self.done.fetch_add(1, Ordering::AcqRel) + 1 == self.n {
                let _g = self.fin.0.lock().expect("pool");
                self.fin.1.notify_all();
            }
        }
    }
}

struct Pool {
    slot: Mutex<(u64, Option<Arc<Job>>)>,
    wake: Condvar,
    workers: usize,
}

fn pool() -> &'static Pool {
    static POOL: OnceLock<&'static Pool> = OnceLock::new();
    POOL.get_or_init(|| {
        let workers = std::thread::available_parallelism().map_or(1, |n| n.get()).min(16).saturating_sub(1);
        let p: &'static Pool = Box::leak(Box::new(Pool { slot: Mutex::new((0, None)), wake: Condvar::new(), workers }));
        for _ in 0..workers {
            std::thread::Builder::new()
                .name("zheng-verify".into())
                .spawn(move || {
                    let mut seen = 0u64;
                    loop {
                        let job = {
                            let mut g = p.slot.lock().expect("pool");
                            while g.0 == seen {
                                g = p.wake.wait(g).expect("pool");
                            }
                            seen = g.0;
                            g.1.clone()
                        };
                        if let Some(j) = job {
                            j.work();
                        }
                    }
                })
                .expect("pool worker");
        }
        p
    })
}

/// `f(i)` for `i < n` on up to `threads` threads (this one included).
pub fn run(n: usize, threads: usize, f: &(dyn Fn(usize) + Sync)) {
    if n == 0 {
        return;
    }
    if threads <= 1 || n == 1 {
        (0..n).for_each(f);
        return;
    }
    let p = pool();
    if p.workers == 0 {
        (0..n).for_each(f);
        return;
    }
    // SAFETY: the lifetime is erased only for the job's duration: this
    // function returns after `done == n`, and no task starts after that.
    let fp: *const (dyn Fn(usize) + Sync) = unsafe { core::mem::transmute::<&(dyn Fn(usize) + Sync), &'static (dyn Fn(usize) + Sync)>(f) };
    let job = Arc::new(Job { f: fp, n, next: AtomicUsize::new(0), done: AtomicUsize::new(0), panicked: AtomicBool::new(false), fin: (Mutex::new(()), Condvar::new()) });
    let _ = threads; // every worker may take tasks; `n` bounds the parallelism
    {
        let mut g = p.slot.lock().expect("pool");
        g.0 += 1;
        g.1 = Some(job.clone());
        p.wake.notify_all();
    }
    job.work();
    {
        let mut g = job.fin.0.lock().expect("pool");
        while job.done.load(Ordering::Acquire) < n {
            g = job.fin.1.wait(g).expect("pool");
        }
    }
    {
        let mut g = p.slot.lock().expect("pool");
        if g.1.as_ref().is_some_and(|j| Arc::ptr_eq(j, &job)) {
            g.1 = None;
        }
    }
    if job.panicked.load(Ordering::Relaxed) {
        panic!("a verifier task panicked");
    }
}

/// `f` over `0..n` in `chunks` contiguous ranges, results in order.
pub fn map_chunks<T: Send>(n: usize, chunks: usize, f: impl Fn(core::ops::Range<usize>) -> T + Sync) -> Vec<T> {
    let chunks = chunks.min(n.max(1)).max(1);
    let size = n.div_ceil(chunks).max(1);
    let count = n.div_ceil(size).max(1);
    let out: Vec<Mutex<Option<T>>> = (0..count).map(|_| Mutex::new(None)).collect();
    run(count, chunks, &|i| {
        let v = f(i * size..((i + 1) * size).min(n));
        *out[i].lock().expect("result") = Some(v);
    });
    out.into_iter().map(|m| m.into_inner().expect("result").expect("every chunk ran")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_task_runs_once_and_results_keep_their_order() {
        for n in [0usize, 1, 2, 7, 100, 1000] {
            for chunks in [1usize, 3, 16] {
                let v = map_chunks(n, chunks, |r| r.clone().map(|i| i * i).collect::<Vec<_>>());
                assert_eq!(v.concat(), (0..n).map(|i| i * i).collect::<Vec<_>>());
            }
        }
        let hits: Vec<AtomicUsize> = (0..500).map(|_| AtomicUsize::new(0)).collect();
        run(500, 16, &|i| {
            hits[i].fetch_add(1, Ordering::Relaxed);
        });
        assert!(hits.iter().all(|h| h.load(Ordering::Relaxed) == 1));
    }

    #[test]
    fn a_panicking_task_panics_the_caller() {
        let r = std::panic::catch_unwind(|| run(64, 16, &|i| assert!(i != 33)));
        assert!(r.is_err());
        // the pool still works
        assert_eq!(map_chunks(10, 4, |r| r.len()).iter().sum::<usize>(), 10);
    }
}
