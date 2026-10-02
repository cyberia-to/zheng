//! Actual fallible evaluation-record allocations in an isolated test binary.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    mem::size_of,
};
use zheng::execution::disclosed::{
    evaluation::{Candidate, Error, Evaluations, Limits, Premises, VerifiedEvaluation},
    memory::{Cost, Definition, Memory, Value, VerifiedNode},
};

thread_local! { static REFUSE: Cell<bool> = const { Cell::new(false) }; }
struct Allocator;
// SAFETY: successful operations delegate unchanged to System. Refusal returns
// null and preserves an existing allocation; deallocation always delegates.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if REFUSE.try_with(Cell::get).unwrap_or(false) {
            std::ptr::null_mut()
        } else {
            // SAFETY: the caller supplies a valid allocation layout.
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if REFUSE.try_with(Cell::get).unwrap_or(false) {
            std::ptr::null_mut()
        } else {
            // SAFETY: the caller supplies a System allocation and valid layout.
            unsafe { System.realloc(ptr, layout, size) }
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: every allocation was delegated to System.
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

#[test]
fn allocation_failures_preserve_verified_evaluations_and_retry_indices() {
    let mut memory = Memory::new(2, 2 * size_of::<VerifiedNode>()).unwrap();
    let atom = nox::data::hash::hash_atom(nebu::Goldilocks::ONE);
    let pair = nox::data::hash::hash_pair(&atom, &atom);
    memory
        .append(Definition {
            value: Value::Atom(1),
            particle: atom.map(|v| v.as_u64()),
            cost: Cost::Exact(0),
        })
        .unwrap();
    memory
        .append(Definition {
            value: Value::Pair { left: 0, right: 0 },
            particle: pair.map(|v| v.as_u64()),
            cost: Cost::Exact(1),
        })
        .unwrap();
    let limits = Limits {
        max_evaluations: 65,
        max_buffer_bytes: 65 * size_of::<VerifiedEvaluation>(),
        max_cost: 1,
        max_frames: 1,
        max_steps: 2,
    };
    let mut evals = Evaluations::new(memory.view(2).unwrap(), limits).unwrap();
    let candidate = Candidate {
        object: 0,
        formula: 1,
        result: 0,
        premises: Premises::None,
    };
    REFUSE.set(true);
    let error = evals.append(candidate);
    REFUSE.set(false);
    assert_eq!(error, Err(Error::Allocation));
    assert!(evals.is_empty());
    assert_eq!(evals.buffer_bytes(), 0);
    for i in 0..64 {
        assert_eq!(evals.append(candidate), Ok(i));
    }
    let before: Vec<_> = (0..64).map(|i| *evals.get(i).unwrap()).collect();
    let bytes = evals.buffer_bytes();
    REFUSE.set(true);
    let error = evals.append(candidate);
    REFUSE.set(false);
    assert_eq!(error, Err(Error::Allocation));
    assert_eq!(evals.len(), 64);
    assert_eq!(evals.buffer_bytes(), bytes);
    for (i, expected) in before.iter().enumerate() {
        assert_eq!(evals.get(i as u32), Ok(expected));
    }
    assert_eq!(evals.append(candidate), Ok(64));
}
