use super::*;
use crate::execution::disclosed::{
    evaluation as dag,
    memory::{Memory, Value, VerifiedNode},
};
use nebu::Goldilocks as F;
use nox::{Outcome, Reduction, data::Data};
use std::collections::BTreeMap;

mod adversarial;
mod boundaries;
mod differential;

const N: usize = 4096;
type Arena = Reduction<N>;
fn atom(ar: &mut Arena, value: u64) -> u32 {
    ar.atom(F::new(value)).unwrap()
}
fn op(ar: &mut Arena, tag: u64, body: u32) -> u32 {
    let head = atom(ar, tag);
    ar.pair(head, body).unwrap()
}
fn quote(ar: &mut Arena, value: u64) -> u32 {
    let value = atom(ar, value);
    op(ar, 1, value)
}
fn binary(ar: &mut Arena, tag: u64, a: u32, b: u32) -> u32 {
    let body = ar.pair(a, b).unwrap();
    op(ar, tag, body)
}
fn branch(ar: &mut Arena, test: u32, yes: u32, no: u32) -> u32 {
    let arms = ar.pair(yes, no).unwrap();
    binary(ar, 4, test, arms)
}
fn pair(ar: &Arena, id: u32) -> (u32, u32) {
    (ar.head(id).unwrap(), ar.tail(id).unwrap())
}
fn particle(ar: &Arena, id: u32) -> super::super::memory::Particle {
    ar.digest(id).unwrap().map(F::as_u64)
}
fn key(ar: &Arena, object: u32, formula: u32) -> InputKey {
    InputKey {
        object: particle(ar, object),
        formula: particle(ar, formula),
    }
}
fn limits() -> Limits {
    Limits {
        max_frames: 128,
        max_cache_slots: 4,
        max_buffer_bytes: SemanticStream::storage_bytes(128, 4).unwrap(),
        max_cost: u64::MAX,
        max_steps: u64::MAX,
        max_events: 100_000,
    }
}

#[derive(Clone, Copy)]
struct Native {
    candidate: dag::Candidate,
    cost: u64,
    peak: u32,
}
fn derive(ar: &mut Arena, object: u32, formula: u32, records: &mut Vec<Native>) -> u32 {
    let (tag, body) = pair(ar, formula);
    let tag = ar.atom_value(tag).unwrap().as_u64();
    let premises = match tag {
        0 | 1 => dag::Premises::None,
        8 | 13 | 15 => dag::Premises::One(derive(ar, object, body, records)),
        4 => {
            let (test, rest) = pair(ar, body);
            let (yes, no) = pair(ar, rest);
            let test = derive(ar, object, test, records);
            let v = ar
                .atom_value(records[test as usize].candidate.result)
                .unwrap();
            let chosen = if v == F::ZERO { yes } else { no };
            dag::Premises::Two([test, derive(ar, object, chosen, records)])
        }
        _ => {
            let (a, b) = pair(ar, body);
            let a = derive(ar, object, a, records);
            let b = derive(ar, object, b, records);
            if tag == 2 {
                let c = derive(
                    ar,
                    records[a as usize].candidate.result,
                    records[b as usize].candidate.result,
                    records,
                );
                dag::Premises::Three([a, b, c])
            } else {
                dag::Premises::Two([a, b])
            }
        }
    };
    let run = nox::sequential::reduce_cached(
        ar,
        object,
        formula,
        u64::MAX,
        nox::sequential::Limits { max_frames: 128 },
    )
    .unwrap();
    let Outcome::Ok(result, remaining) = run.outcome else {
        panic!("{:?}", run.outcome)
    };
    let id = records.len() as u32;
    records.push(Native {
        candidate: dag::Candidate {
            object,
            formula,
            result,
            premises,
        },
        cost: u64::MAX - remaining,
        peak: run.peak_frames,
    });
    id
}

/// A wholly new table containing only the requested reachable nouns. Varying
/// padding remaps occurrence IDs; parent formulas are absent from finish views.
fn snapshot(ar: &Arena, roots: &[u32], nonce: u32) -> (Memory, Vec<u32>) {
    fn add(ar: &Arena, id: u32, memory: &mut Memory, map: &mut BTreeMap<u32, u32>) -> u32 {
        if let Some(&id) = map.get(&id) {
            return id;
        }
        let value = match ar.get(id).unwrap().inner {
            Data::Atom { value } => Value::Atom(value.as_u64()),
            Data::Pair { left, right } => Value::Pair {
                left: add(ar, left, memory, map),
                right: add(ar, right, memory, map),
            },
        };
        let out = memory.append_value(value).unwrap();
        map.insert(id, out);
        out
    }
    let mut memory = Memory::new(
        ar.count() + 4,
        (ar.count() as usize + 4) * size_of::<VerifiedNode>(),
    )
    .unwrap();
    for n in 0..1 + nonce % 3 {
        memory
            .append_value(Value::Atom(100_000 + u64::from(n)))
            .unwrap();
    }
    let mut map = BTreeMap::new();
    let ids = roots
        .iter()
        .map(|&id| add(ar, id, &mut memory, &mut map))
        .collect();
    (memory, ids)
}
fn enter(
    stream: &mut SemanticStream,
    ar: &Arena,
    object: u32,
    formula: u32,
    nonce: &mut u32,
) -> Result<(), Error> {
    *nonce += 1;
    let (memory, ids) = snapshot(ar, &[object, formula], *nonce);
    stream.enter(&memory.view(memory.len()).unwrap(), ids[0], ids[1])
}
fn finish(
    stream: &mut SemanticStream,
    ar: &Arena,
    result: u32,
    slot: Option<u32>,
    nonce: &mut u32,
) -> Result<Option<CacheHandle>, Error> {
    *nonce += 1;
    let (memory, ids) = snapshot(ar, &[result], *nonce);
    stream.finish(&memory.view(memory.len()).unwrap(), ids[0], slot)
}

fn emit(stream: &mut SemanticStream, ar: &Arena, records: &[Native], id: u32, nonce: &mut u32) {
    let c = records[id as usize].candidate;
    assert_eq!(stream.expected(), Some(key(ar, c.object, c.formula)));
    enter(stream, ar, c.object, c.formula, nonce).unwrap();
    for &child in c.premises.as_slice() {
        emit(stream, ar, records, child, nonce);
    }
    assert_eq!(stream.expected(), None);
    finish(stream, ar, c.result, None, nonce).unwrap();
}
fn claim(ar: &Arena, native: Native) -> Claim {
    let c = native.candidate;
    Claim {
        object: particle(ar, c.object),
        formula: particle(ar, c.formula),
        result: particle(ar, c.result),
        cost: native.cost,
        budget: native.cost,
        max_frames: native.peak,
    }
}
fn terminal(ar: &Arena, records: &[Native]) -> VerifiedTerminal {
    let last = *records.last().unwrap();
    let mut stream = SemanticStream::new(
        key(ar, last.candidate.object, last.candidate.formula),
        limits(),
    )
    .unwrap();
    emit(&mut stream, ar, records, records.len() as u32 - 1, &mut 0);
    stream.bind_terminal(claim(ar, last)).unwrap()
}
fn finite(ar: &Arena, records: &[Native]) -> dag::VerifiedEvaluation {
    let mut memory =
        Memory::new(ar.count(), ar.count() as usize * size_of::<VerifiedNode>()).unwrap();
    for id in 0..ar.count() {
        let value = match ar.get(id).unwrap().inner {
            Data::Atom { value } => Value::Atom(value.as_u64()),
            Data::Pair { left, right } => Value::Pair { left, right },
        };
        memory.append_value(value).unwrap();
    }
    let n = records.len() as u32;
    let mut dag = dag::Evaluations::new(
        memory.view(memory.len()).unwrap(),
        dag::Limits {
            max_evaluations: n,
            max_buffer_bytes: n as usize * size_of::<dag::VerifiedEvaluation>(),
            max_cost: u64::MAX,
            max_steps: u64::MAX,
            max_frames: 128,
        },
    )
    .unwrap();
    for record in records {
        dag.append(record.candidate).unwrap();
    }
    *dag.get(n - 1).unwrap()
}
