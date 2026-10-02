//! Exercise the actual fallible allocation boundary in an isolated test binary.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
use zheng::execution::disclosed::memory::{Cost, Definition, Error, Memory, Value, VerifiedNode};

thread_local! { static REFUSE: Cell<bool> = const { Cell::new(false) }; }
struct Allocator;

// SAFETY: accepted operations delegate unchanged to System. A refused
// allocation returns null as required by GlobalAlloc; deallocation is preserved.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if REFUSE.try_with(Cell::get).unwrap_or(false) {
            std::ptr::null_mut()
        }
        // SAFETY: the caller supplies the layout required by GlobalAlloc.
        else {
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: every non-null allocation originated from System.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if REFUSE.try_with(Cell::get).unwrap_or(false) {
            std::ptr::null_mut()
        }
        // SAFETY: the caller supplies the original allocation and valid layout.
        else {
            unsafe { System.realloc(ptr, layout, size) }
        }
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn atom(value: u64) -> Definition {
    Definition {
        value: Value::Atom(value),
        particle: nox::data::hash::hash_atom(nebu::Goldilocks::new(value)).map(|x| x.as_u64()),
        cost: Cost::Exact(0),
    }
}

#[test]
fn failed_growth_preserves_validated_records_and_allows_retry() {
    let mut memory = Memory::new(65, 65 * std::mem::size_of::<VerifiedNode>()).unwrap();
    let first = atom(0);
    REFUSE.set(true);
    let result = memory.append(first);
    REFUSE.set(false);
    assert_eq!(result, Err(Error::Allocation));
    assert!(memory.is_empty());
    assert_eq!(memory.buffer_bytes(), 0);
    for i in 0..64 {
        memory.append(atom(i)).unwrap();
    }
    let expected: Vec<_> = (0..64).map(atom).collect();
    let next = atom(64);
    let before_bytes = memory.buffer_bytes();
    REFUSE.set(true);
    let result = memory.append(next);
    REFUSE.set(false);
    assert_eq!(result, Err(Error::Allocation));
    assert_eq!(memory.len(), 64);
    assert_eq!(memory.buffer_bytes(), before_bytes);
    let view = memory.view(64).unwrap();
    for (i, definition) in expected.iter().enumerate() {
        let got = view.bind(i as u32, definition.particle).unwrap();
        assert_eq!(got.value(), definition.value);
        assert_eq!(got.cost(), definition.cost);
    }
    assert_eq!(memory.append(next), Ok(64));
}
