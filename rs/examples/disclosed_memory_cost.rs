//! Bounded native-DAG memory-admission measurement, not an execution proof.
use nox::{Reduction, data::Data};
use std::{mem::size_of, time::Instant};
use zheng::execution::disclosed::memory::{Cost, Definition, Memory, Value, VerifiedNode};

fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        return Err("usage: disclosed_memory_cost <atom-count: 2..=65536>".into());
    }
    let count: u32 = args[1].parse().map_err(|_| "invalid atom count")?;
    if !(2..=65536).contains(&count) {
        return Err("atom count outside declared range".into());
    }
    let start = Instant::now();
    let mut arena = Reduction::<262144>::try_new_boxed().map_err(|e| format!("arena: {e:?}"))?;
    for i in 0..count {
        arena
            .atom(nebu::Goldilocks::new(u64::from(i)))
            .ok_or("atom capacity")?;
    }
    for i in 1..count {
        arena.pair(i - 1, i).ok_or("pair capacity")?;
    }
    let mut definitions = Vec::with_capacity(arena.count() as usize);
    for i in 0..arena.count() {
        let n = arena.get(i).ok_or("missing native node")?;
        definitions.push(Definition {
            value: match n.inner {
                Data::Atom { value } => Value::Atom(value.as_u64()),
                Data::Pair { left, right } => Value::Pair { left, right },
            },
            particle: n.hash.map(|x| x.as_u64()),
            cost: if n.bound.is_dynamic() {
                Cost::Dynamic(n.bound.value())
            } else {
                Cost::Exact(n.bound.value())
            },
        });
    }
    let fixture_ns = start.elapsed().as_nanos();
    let nodes = arena.count();
    drop(arena);
    let start = Instant::now();
    let mut memory = Memory::new(nodes, nodes as usize * size_of::<VerifiedNode>())
        .map_err(|e| format!("table: {e:?}"))?;
    for definition in definitions {
        memory
            .append(definition)
            .map_err(|e| format!("admission: {e:?}"))?;
    }
    let verify_ns = start.elapsed().as_nanos();
    println!(
        "{}",
        serde_json::json!({
            "scope": "native noun/Cost admission only; no execution certificate",
            "atoms": count, "pairs": nodes-count, "records": nodes,
            "record_storage_bytes": size_of::<VerifiedNode>(),
            "record_buffer_bytes": memory.buffer_bytes(),
            "native_fixture_ns": fixture_ns, "complete_admission_ns": verify_ns
        })
    );
    Ok(())
}
