//! Actual allocation failures and allocation-free events in an isolated binary.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    mem::size_of,
};
use zheng::execution::disclosed::{
    memory::{Memory, Value, VerifiedNode},
    stream::{Claim, Error, InputKey, Limits, SemanticStream},
};

// None delegates normally; Some(n) allows n allocation attempts before refusal.
thread_local! { static ALLOW: Cell<Option<usize>> = const { Cell::new(None) }; }
fn refuse() -> bool {
    ALLOW
        .try_with(|remaining| match remaining.get() {
            None => false,
            Some(0) => true,
            Some(n) => {
                remaining.set(Some(n - 1));
                false
            }
        })
        .unwrap_or(false)
}
struct Allocator;
// SAFETY: accepted operations delegate unchanged to System. Refusal returns
// null, preserving any existing allocation. Deallocation always delegates.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if refuse() {
            std::ptr::null_mut()
        } else {
            // SAFETY: the caller supplies a valid layout.
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if refuse() {
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
fn constructor_failures_are_fallible_and_events_need_no_allocations() {
    let mut memory = Memory::new(8, 8 * size_of::<VerifiedNode>()).unwrap();
    // Quote 7, then cons its two repeated evaluations, producing [7 7].
    for value in [
        Value::Atom(1),
        Value::Atom(7),
        Value::Atom(3),
        Value::Pair { left: 0, right: 1 },
        Value::Pair { left: 3, right: 3 },
        Value::Pair { left: 2, right: 4 },
        Value::Pair { left: 1, right: 1 },
    ] {
        memory.append_value(value).unwrap();
    }
    let view = memory.view(memory.len()).unwrap();
    let root = InputKey {
        object: view.get(1).unwrap().particle(),
        formula: view.get(5).unwrap().particle(),
    };
    let limits = Limits {
        max_frames: 2,
        max_cache_slots: 1,
        max_buffer_bytes: SemanticStream::storage_bytes(2, 1).unwrap(),
        max_cost: 3,
        max_steps: 6,
        max_events: 5,
    };
    for allowed in [0, 1] {
        ALLOW.set(Some(allowed));
        let failure = SemanticStream::new(root, limits);
        ALLOW.set(None);
        assert!(matches!(failure, Err(Error::Allocation)));
    }
    let mut stream = SemanticStream::new(root, limits).unwrap();
    ALLOW.set(Some(0));
    let run = (|| {
        stream.enter(&view, 1, 5)?;
        stream.enter(&view, 1, 3)?;
        let cached = stream.finish(&view, 1, Some(0))?.ok_or(Error::Cache)?;
        stream.reuse(cached)?;
        stream.finish(&view, 6, None)?;
        stream.bind_terminal(Claim {
            object: root.object,
            formula: root.formula,
            result: view.get(6).unwrap().particle(),
            cost: 3,
            budget: 3,
            max_frames: 2,
        })
    })();
    ALLOW.set(None);
    let done = run.unwrap();
    assert_eq!(
        (done.summary().cost(), done.summary().steps(), done.events()),
        (3, 6, 5)
    );
}
